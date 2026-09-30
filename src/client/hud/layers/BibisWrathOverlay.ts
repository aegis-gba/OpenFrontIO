import { html, LitElement } from "lit";
import { customElement, state } from "lit/decorators.js";
import {
  BibisWrathEventUpdate,
  GameUpdateType,
} from "../../../core/game/GameUpdates";
import { Controller } from "../../Controller";
import { GameView } from "../../view";
import bibisWrathVsUrl from "../../../../resources/images/BibisWrathVs.jpg";

// How long the VS splash stays on screen.
const BIBIS_WRATH_DISPLAY_MS = 5000;

// "Bibi's Wrath": a fullscreen VS splash on every connected client.
// The admin's name goes in the left name box, the chosen player's in the
// right one. Shown for 5 seconds, pointer-events pass through so the game
// stays playable underneath.
@customElement("bibis-wrath-overlay")
export class BibisWrathOverlay extends LitElement implements Controller {
  public game: GameView;

  @state()
  private adminName: string | null = null;

  @state()
  private targetName: string | null = null;

  private hideTimeout: number | null = null;

  createRenderRoot() {
    return this;
  }

  disconnectedCallback() {
    super.disconnectedCallback();
    if (this.hideTimeout) {
      clearTimeout(this.hideTimeout);
      this.hideTimeout = null;
    }
  }

  tick() {
    if (!this.game) return;
    const updates = this.game.updatesSinceLastTick();
    const wraths = updates?.[GameUpdateType.BibisWrathEvent] as
      | BibisWrathEventUpdate[]
      | undefined;
    if (wraths && wraths.length > 0) {
      const last = wraths[wraths.length - 1];
      this.show(last.adminName, last.targetName);
    }
  }

  private show(adminName: string, targetName: string) {
    this.adminName = adminName;
    this.targetName = targetName;
    this.requestUpdate();
    if (this.hideTimeout) {
      clearTimeout(this.hideTimeout);
    }
    this.hideTimeout = window.setTimeout(() => {
      this.adminName = null;
      this.targetName = null;
      this.hideTimeout = null;
      this.requestUpdate();
    }, BIBIS_WRATH_DISPLAY_MS);
  }

  render() {
    if (!this.adminName || !this.targetName) return html``;
    return html`
      <div
        class="fixed inset-0 z-[9999] flex items-center justify-center"
        style="pointer-events: none;"
      >
        <div class="wrath-frame">
          <img
            src="${bibisWrathVsUrl}"
            alt="Versus"
            class="wrath-img"
            draggable="false"
          />
          <div class="wrath-name wrath-name-left">${this.adminName}</div>
          <div class="wrath-name wrath-name-right">${this.targetName}</div>
        </div>
      </div>
      <style>
        .wrath-frame {
          position: relative;
          width: min(96vw, 1100px);
          aspect-ratio: 1170 / 658;
          container-type: inline-size;
          animation: wrath-pop 5s ease-out forwards;
          filter: drop-shadow(0 0 40px rgba(0, 0, 0, 0.8));
        }
        .wrath-img {
          width: 100%;
          height: 100%;
          object-fit: contain;
          user-select: none;
        }
        .wrath-name {
          position: absolute;
          top: 5.2%;
          height: 11.4%;
          display: flex;
          align-items: center;
          justify-content: center;
          font-weight: 900;
          color: #111;
          font-size: 5.2cqw;
          line-height: 1;
          white-space: nowrap;
          overflow: hidden;
          text-overflow: ellipsis;
          padding: 0 1cqw;
          font-family: inherit;
        }
        .wrath-name-left {
          left: 3.8%;
          width: 42%;
        }
        .wrath-name-right {
          left: 54.2%;
          width: 42%;
        }
        @keyframes wrath-pop {
          0% {
            transform: scale(0.65);
            opacity: 0;
          }
          7% {
            transform: scale(1.03);
            opacity: 1;
          }
          11% {
            transform: scale(1);
          }
          86% {
            transform: scale(1);
            opacity: 1;
          }
          100% {
            transform: scale(1.06);
            opacity: 0;
          }
        }
      </style>
    `;
  }
}
