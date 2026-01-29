// views/screen5.js
// Screen 5 — Integration Wizard (4 phases) — Mongolian, dropdown/radio focused UX
// Supports editable copy (texts) via `copy` object (e.g., loaded from SQLite).

function esc(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function option(value, current) {
  const v = esc(value);
  return `<option value="${v}" ${String(current)===String(value)?"selected":""}>${v}</option>`;
}

function radio(name, value, current, label) {
  const v = esc(value);
  const checked = String(current)===String(value) ? "checked" : "";
  return `<label class="radio"><input type="radio" name="${esc(name)}" value="${v}" ${checked}/> ${esc(label ?? value)}</label>`;
}

const BODY_LOCATIONS = ["Толгой","Нүүр","Хоолой","Цээж","Гэдэс","Нуруу","Гар","Хөл","Бүх бие"];
const RELEASE_LOCATIONS = ["Толгой","Хоолой","Цээж","Гэдэс","Гар","Хөл","Бусад"];
const P2_SHAPES = ["Хатуу","Зөөлөн","Дүүрэн","Даралттай","Хөнгөн","Чангаралттай","Хөдөлгөөнтэй","Хөдөлгөөнгүй","Бусад"];

// ---- Editable copy (defaults) ----
// Store values as plain text. For dynamic bits, use {emotion} placeholder.
const DEFAULT_COPY = {
  safety_note:
    "Аюулгүй байдал: энэ нь эмчилгээ/онош биш. Хэт хүчтэй болж, бие махбодын аюул мэдрэгдвэл зогсоод амьсгал + ус уугаад амар. Хэрэв өөртөө эсвэл бусдад хор хүргэх бодол төрвөл яаралтай тусламж/ойр дотнын хүнтэйгээ холбогдоорой.",

  small_rules_title: "Жижиг дүрэм",
  small_rules_body:
    "Алхам бүр дээр 1 минут орчим зогсоод биеэ ажигла. Зорилго нь ‘алга болгох’ биш — тэсвэрлэх чадвар + зөвшөөрөх.",
  timer_hint:
    "Алхам бүр дээр 1 минут зогсоод ажиглана. 1 минут дууссаны дараа үргэлжлүүлэх боломжтой.",

  // --- Editable labels & options (admin) ---
  lbl_emotion: "Одоогийн мэдрэмж",
  opt_emotions: "Айдас\nУур\nГуниг\nИчгүүр\nБаяр хөөр",

  lbl_p1_bodyLocation: "Биеийн аль хэсэгт хамгийн тод байна?",
  opt_bodyLocations: "Толгой\nНүүр\nХоолой\nЦээж\nГэдэс\nНуруу\nГар\nХөл\nБүх бие",
  lbl_p1_breathing: "Амьсгал чинь ямар байна вэ?",
  opt_breathing: "Түргэн\nУдаан\nЖигд",

  lbl_intensity_before: "Энэ мэдрэмжийн хүчийг 0–10 үнэлгээ өг",
  lbl_intensity_after: "Энэ мэдрэмжийн хүчийг 0–10 үнэлгээ өг",
  lbl_intensity_optional: "(optional)",
  lbl_intensity_note: "Үнэлгээ өгсний дараа мэдрэмжээ 1–2 өгүүлбэрээр бич",
  ph_intensity_note: "Ж: Цээж базалж, амьсгал давчдана...",

  lbl_p2_fixing: "Энэ мэдрэмжийг засах хэрэгтэй юм шиг санагдаж байна уу?",
  opt_yesno: "Тийм\nҮгүй",
  lbl_p2_observing: "Энэ мэдрэмж ямар хэлбэртэй байна?",
  opt_p2_shapes: "Хатуу\nЗөөлөн\nДүүрэн\nДаралттай\nХөнгөн\nЧангаралттай\nХөдөлгөөнтэй\nХөдөлгөөнгүй",

  lbl_p3_release: "Бие дээр сулрал / дулаан / чимчигнэх гарч байна уу?",
  lbl_p3_releaseLocation: "Хэрвээ тийм бол хаана?",
  opt_releaseLocations: "Толгой\nХоолой\nЦээж\nГэдэс\nГар\nХөл",
  lbl_p3_staying: "Үүнийг ажиглаад суухад ямар байна?",
  opt_easyhard: "Амархан\nХэцүү",
  hint_releaseLocation_disabled: "Тийм сонгосон үед идэвхжнэ.",

  lbl_p4_change: "Эхний мэдрэмж өөрчлөгдсөн үү?",
  opt_change: "Бага\nИх\nӨөрчлөлтгүй",
  lbl_p4_insight: "Нэг өгүүлбэрээр: өнөөдөр чи юуг ‘засахгүйгээр’ зөвшөөрөв? (заавал бөглөнө)",
  ph_p4_insight: "Жнь Би айдас байгааг мэдэрлээ, Айдас бол би биш түүнийг миний биед байхыг зөвшөөрч чадсан. Эсвэл айдас маш хүчтэй орж ирлээ би байж сууж чадахгүй хяналтаа алдаж өөр юм хийсэн",

  btn_back: "Буцах",
  btn_next: "Үргэлжлүүлэх",
  btn_complete: "Дуусгах",
  btn_back_journal: "Буцах (Journal)",


  p1_sub: "Дотроо өөртөө хэл. Одоо миний бие аюулгүй байна. Бие дээрээ зөөлөн анхаарлаа төвлөрүүл (30–90 сек).",
  p1_guide_title: "Чиглүүлэг",
  p1_guide_body: "Биед мэдрэгдэж байгаа мэдрэмжийг засах гэж оролдохгүй. Зүгээр л нэр өгөөд, дотогшоо мэдрээд хүлээн зөвшөөр.",
  p1_mantra: "Хамраараа урт гүнзгий амьсгал аваад, удаанаар гарга (5 удаа) ",
  p1_li1:
    "Жишээ өгүүлбэр: “Би яаг одоо цээж дүүрэн шахалт өгсөн өвдөлт мэдэрч байна. би чамайг Айдас гэж нэрлэе”",
  p1_li2:
    " Чамайг би харж бас мэдэрч байна, чи энд байж болно би чамайг энд байхыг хүлээн зөвшөөрч байна.",

  p2_sub: "Мэдрэмжийг өөрчлөх гэж оролдохгүй, түлхэхгүй. Байгаагаар нь зөвшөөр (30–90 сек).",
  p2_guide_title: "Чиглүүлэг",
  p2_guide_body: "Чиний зорилго — ‘алга болгох’ биш. ‘Зөвшөөрөөд’ үлдэх.",
  p2_li1: "Өөрийн сэтгэл хөдлөл мэдрэмжид тавих асуулт: “Чи юуг анхааруулах гэж байна вэ? Чи юуг хамгаалах гэж энд гарч ирэв? Хэрвээ чи дуу хоолойтой бол надад юу хэлэх вэ? Хариу нь: үг биш, дүр зураг, дурсамж, эсвэл зүгээр мэдрэмж байж болно, сайн ажиглаарай.",
  p2_li2: "Жишээ өгүүлбэр: “Одоо би засахгүй. Зөвхөн ажиглана.”",

  p3_sub: "Чи зөвхөн ажиглагч байгарай. Бие өөрөө зохицуулна. (30–90 сек).",
  p3_guide_title: "Чиглүүлэг",
  p3_guide_body: "Өөрчлөлт заавал том байх албагүй. Жижиг долгион ч байж болно.",
  p3_li1:
    "Анзаарах зүйл: амьсгал гүнзгийрэх, дулаарах, чичрэх, нулимс, эвшээх, санаа алдах",
  p3_li2: "Жишээ өгүүлбэр: “Бие өөрөө хөдөлж байна. Би зөвшөөрнө.”",

  p4_sub: "Одоо юу өөрчлөгдсөн бэ? (30–60 сек)",
  p4_accept_title: "Хүлээн зөвшөөрөл",
  p4_accept_body:
    "Би чамайг харлаа. Чи бол {emotion} байна. Би чамайг энд байхыг хүлээн зөвшөөрч байна.",

  p4_reflect_title: "Reflection prompt",
  p4_reflect_li1: "Асуулт: “Энэ мэдрэмж надад яг юу хэлэх гээд байна вэ?”",
  p4_reflect_li2: "Асуулт: “Би өнөөдөр юуг хүндэтгээд, юу ‘засахгүйгээр’ зөвшөөрөв?”",
  p4_reflect_li3:
    "Жишээ: “Би яарахгүй байж чадна.” / “Алдаа гаргасан ч би өөрийгөө хаяхгүй.”"
};


function parseLines(s) {
  return String(s ?? "")
    .split(/\r?\n/)
    .map(x => x.trim())
    .filter(Boolean);
}

function pickList(copy, key, fallbackArr) {
  const raw = pickCopy(copy, key, "");
  const arr = parseLines(raw);
  return arr.length ? arr : (fallbackArr || []);
}

function pickCopy(copy, key, fallback = "") {
  const v = copy && Object.prototype.hasOwnProperty.call(copy, key) ? copy[key] : undefined;
  const s = (v === null || v === undefined) ? fallback : String(v);
  return s;
}

function headerKpis(cur, emotion) {
  return `
    <div class="kpis" style="margin-top:10px">
      <span class="kpi">Step ${cur}/4</span>
      <span class="kpi">Мэдрэмж: ${esc(emotion || "Тодорхойгүй")}</span>
    </div>
  `;
}

function safetyNote(copy) {
  const txt = pickCopy(copy, "safety_note", DEFAULT_COPY.safety_note);
  return `
    <div class="small safety" style="margin-top:10px" data-copy="safety_note">${esc(txt)}</div>
  `;
}

function phase1(st, copy) {
  const p1_sub = pickCopy(copy, "p1_sub", DEFAULT_COPY.p1_sub);
  const p1_guide_title = pickCopy(copy, "p1_guide_title", DEFAULT_COPY.p1_guide_title);
  const p1_guide_body = pickCopy(copy, "p1_guide_body", DEFAULT_COPY.p1_guide_body);
  const p1_mantra = pickCopy(copy, "p1_mantra", DEFAULT_COPY.p1_mantra);
  const p1_li1 = pickCopy(copy, "p1_li1", DEFAULT_COPY.p1_li1);
  const p1_li2 = pickCopy(copy, "p1_li2", DEFAULT_COPY.p1_li2);
  return `
    <h3 style="margin:0">1-р шат</h3>
    <div class="small muted" style="margin-top:6px" data-copy="p1_sub">${esc(p1_sub)}</div>

    <div class="small therapy-box" style="margin-top:8px; padding:12px; border-radius:12px;">
      <div style="font-weight:700; font-size:15px; margin-bottom:8px" data-copy="p1_guide_title">${esc(p1_guide_title)}</div>
      <div class="muted" data-copy="p1_guide_body">${esc(p1_guide_body)}</div>
      <div style="margin-top:10px; font-weight:700" data-copy="p1_mantra">${esc(p1_mantra)}</div>
      <ul style="margin:8px 0 0 18px">
        <li><span class="muted"></span><span data-copy="p1_li1">${esc(p1_li1)}</span></li>
        <li><span class="muted"></span><span data-copy="p1_li2">${esc(p1_li2)}</span></li>
      </ul>
    </div>

    <div class="row" style="margin-top:10px">
      <div class="field" style="min-width:260px">
        <label data-copy="lbl_p1_bodyLocation">${esc(pickCopy(copy,"lbl_p1_bodyLocation", DEFAULT_COPY.lbl_p1_bodyLocation))}</label>
        <select name="p1_bodyLocation">
          ${pickList(copy,"opt_bodyLocations", BODY_LOCATIONS).map(x => option(x, st.p1_bodyLocation)).join("")}
        </select>
      </div>

      <div class="field" style="min-width:260px">
        <label data-copy="lbl_p1_breathing">${esc(pickCopy(copy,"lbl_p1_breathing", DEFAULT_COPY.lbl_p1_breathing))}</label>
        <select name="p1_breathing">
          ${pickList(copy,"opt_breathing", ["Түргэн","Удаан","Жигд"]).map(x => option(x, st.p1_breathing)).join("")}
        </select>
      </div>
    </div>

    <div class="row" style="margin-top:10px">
      <div class="field" style="max-width:220px">
        <label>${esc(pickCopy(copy,"lbl_intensity_before", DEFAULT_COPY.lbl_intensity_before))} <span class="muted">${esc(pickCopy(copy,"lbl_intensity_optional", DEFAULT_COPY.lbl_intensity_optional))}</span></label>
        <input name="intensityBefore" inputmode="numeric" placeholder="0-10" value="${esc(st.intensityBefore)}" />
      </div>
    </div>

    <div class="field" style="margin-top:10px">
      <label data-copy="lbl_intensity_note">${esc(pickCopy(copy,"lbl_intensity_note", DEFAULT_COPY.lbl_intensity_note))} <span class="muted">${esc(pickCopy(copy,"lbl_intensity_optional", DEFAULT_COPY.lbl_intensity_optional))}</span></label>
      <textarea name="p1_intensityNote" rows="3" placeholder="Жишээ: Цээжинд шахалт 9/10 байна. Энэ мэдрэмж халуун бас хүчтэй дээшээ доошоо хөдөлж байна.Би үүнийг айдас гэж нэрлэе Би үүнийг 30 сек ажиглана.">${esc(st.p1_intensityNote)}</textarea>
    </div>

  `;
}

function phase2(st, copy) {
  const p2_sub = pickCopy(copy, "p2_sub", DEFAULT_COPY.p2_sub);
  const p2_guide_title = pickCopy(copy, "p2_guide_title", DEFAULT_COPY.p2_guide_title);
  const p2_guide_body = pickCopy(copy, "p2_guide_body", DEFAULT_COPY.p2_guide_body);
  const p2_li1 = pickCopy(copy, "p2_li1", DEFAULT_COPY.p2_li1);
  const p2_li2 = pickCopy(copy, "p2_li2", DEFAULT_COPY.p2_li2);
  return `
    <h3 style="margin:0">2-р шат</h3>
    <div class="small muted" style="margin-top:6px" data-copy="p2_sub">${esc(p2_sub)}</div>

    <div class="callout">
      <div style="font-weight:600; margin-bottom:6px" data-copy="p2_guide_title">${esc(p2_guide_title)}</div>
      <div class="muted" data-copy="p2_guide_body">${esc(p2_guide_body)}</div>
      <ul style="margin:8px 0 0 18px">
        <li><span data-copy="p2_li1">${esc(p2_li1)}</span></li>
        <li><span data-copy="p2_li2">${esc(p2_li2)}</span></li>
      </ul>
    </div>

    <div class="row" style="margin-top:10px">
      <div class="field" style="min-width:260px">
        <label data-copy="lbl_p2_fixing">${esc(pickCopy(copy,"lbl_p2_fixing", DEFAULT_COPY.lbl_p2_fixing))}</label>
        <select name="p2_fixing">
          ${pickList(copy,"opt_yesno", ["Тийм","Үгүй"]).map(x => option(x, st.p2_fixing)).join("")}
        </select>
      </div>

      <div class="field" style="min-width:260px">
        <label data-copy="lbl_p2_observing">${esc(pickCopy(copy,"lbl_p2_observing", DEFAULT_COPY.lbl_p2_observing))}</label>
        <select name="p2_observing">
          ${pickList(copy,"opt_p2_shapes", P2_SHAPES).map(x => option(x, st.p2_observing)).join("")}
        </select>
      </div>
    </div>
  `;
}

function phase3(st, copy) {
  const p3_sub = pickCopy(copy, "p3_sub", DEFAULT_COPY.p3_sub);
  const p3_guide_title = pickCopy(copy, "p3_guide_title", DEFAULT_COPY.p3_guide_title);
  const p3_guide_body = pickCopy(copy, "p3_guide_body", DEFAULT_COPY.p3_guide_body);
  const p3_li1 = pickCopy(copy, "p3_li1", DEFAULT_COPY.p3_li1);
  const p3_li2 = pickCopy(copy, "p3_li2", DEFAULT_COPY.p3_li2);
  const rel = st.p3_release ?? "Үгүй";
  return `
    <h3 style="margin:0">3-р шат</h3>
    <div class="small muted" style="margin-top:6px" data-copy="p3_sub">${esc(p3_sub)}</div>

    <div class="callout">
      <div style="font-weight:600; margin-bottom:6px" data-copy="p3_guide_title">${esc(p3_guide_title)}</div>
      <div class="muted" data-copy="p3_guide_body">${esc(p3_guide_body)}</div>
      <ul style="margin:8px 0 0 18px">
        <li><span data-copy="p3_li1">${esc(p3_li1)}</span></li>
        <li><span data-copy="p3_li2">${esc(p3_li2)}</span></li>
      </ul>
    </div>

    <div class="row" style="margin-top:10px">
      <div class="field" style="min-width:260px">
        <label data-copy="lbl_p3_release">${esc(pickCopy(copy,"lbl_p3_release", DEFAULT_COPY.lbl_p3_release))}</label>
        <select name="p3_release">
          ${pickList(copy,"opt_yesno", ["Тийм","Үгүй"]).map(x => option(x, rel)).join("")}
        </select>
      </div>

      <div class="field" style="min-width:260px">
        <label data-copy="lbl_p3_releaseLocation">${esc(pickCopy(copy,"lbl_p3_releaseLocation", DEFAULT_COPY.lbl_p3_releaseLocation))}</label>
        <select name="p3_releaseLocation" ${rel==="Тийм" ? "" : "disabled"}>
          ${pickList(copy,"opt_releaseLocations", RELEASE_LOCATIONS).map(x => option(x, st.p3_releaseLocation)).join("")}
        </select>
        <div class="small muted" style="margin-top:4px">${rel==="Тийм" ? "" : "Тийм сонгосон үед идэвхжнэ."}</div>
      </div>
    </div>

    <div class="row" style="margin-top:10px">
      <div class="field" style="min-width:260px">
        <label data-copy="lbl_p3_staying">${esc(pickCopy(copy,"lbl_p3_staying", DEFAULT_COPY.lbl_p3_staying))}</label>
        <select name="p3_staying">
          ${pickList(copy,"opt_easyhard", ["Амархан","Хэцүү"]).map(x => option(x, st.p3_staying)).join("")}
        </select>
      </div>
    </div>
  `;
}

function phase4(st, copy) {
  const p4_sub = pickCopy(copy, "p4_sub", DEFAULT_COPY.p4_sub);
  const p4_accept_title = pickCopy(copy, "p4_accept_title", DEFAULT_COPY.p4_accept_title);
  const p4_accept_body_tmpl = pickCopy(copy, "p4_accept_body", DEFAULT_COPY.p4_accept_body);
  const p4_reflect_title = pickCopy(copy, "p4_reflect_title", DEFAULT_COPY.p4_reflect_title);
  const p4_reflect_li1 = pickCopy(copy, "p4_reflect_li1", DEFAULT_COPY.p4_reflect_li1);
  const p4_reflect_li2 = pickCopy(copy, "p4_reflect_li2", DEFAULT_COPY.p4_reflect_li2);
  const p4_reflect_li3 = pickCopy(copy, "p4_reflect_li3", DEFAULT_COPY.p4_reflect_li3);
  const emo = st.emotion || "Тодорхойгүй";
  const acceptText = p4_accept_body_tmpl.replaceAll("{emotion}", emo);
  return `
    <h3 style="margin:0">4-р шат</h3>
    <div class="small muted" style="margin-top:6px" data-copy="p4_sub">${esc(p4_sub)}</div>

    <div class="callout">
      <div style="font-weight:600; margin-bottom:6px" data-copy="p4_accept_title">${esc(p4_accept_title)}</div>
      <div class="muted" data-copy="p4_accept_body" data-emotion="${esc(emo)}">${esc(acceptText)}</div>
    </div>

    <div class="callout">
      <div style="font-weight:600; margin-bottom:6px" data-copy="p4_reflect_title">${esc(p4_reflect_title)}</div>
      <ul style="margin:8px 0 0 18px">
        <li><span data-copy="p4_reflect_li1">${esc(p4_reflect_li1)}</span></li>
        <li><span data-copy="p4_reflect_li2">${esc(p4_reflect_li2)}</span></li>
        <li><span data-copy="p4_reflect_li3">${esc(p4_reflect_li3)}</span></li>
      </ul>
    </div>

    <div class="row" style="margin-top:10px">
      <div class="field" style="min-width:260px">
        <label data-copy="lbl_p4_change">${esc(pickCopy(copy,"lbl_p4_change", DEFAULT_COPY.lbl_p4_change))}</label>
        <select name="p4_change">
          ${pickList(copy,"opt_change", ["Бага","Их","Өөрчлөлтгүй"]).map(x => option(x, st.p4_change)).join("")}
        </select>
      </div>

      <div class="field" style="max-width:220px">
        <label>${esc(pickCopy(copy,"lbl_intensity_before", DEFAULT_COPY.lbl_intensity_before))} <span class="muted">${esc(pickCopy(copy,"lbl_intensity_optional", DEFAULT_COPY.lbl_intensity_optional))}</span></label>
        <input name="intensityAfter" inputmode="numeric" placeholder="0-10" value="${esc(st.intensityAfter)}" />
      </div>
    </div>

    <div class="field" style="margin-top:10px">
      <label data-copy="lbl_p4_insight">${esc(pickCopy(copy,"lbl_p4_insight", DEFAULT_COPY.lbl_p4_insight))}</label>
      <textarea name="p4_insight" rows="3" placeholder="${esc(pickCopy(copy,"ph_p4_insight", DEFAULT_COPY.ph_p4_insight))}">${esc(st.p4_insight)}</textarea>
    </div>
  `;
}

function emotionPicker(st, copy) {
  return `
    <div class="row">
      <div class="field" style="min-width:260px">
        <label data-copy="lbl_emotion">${esc(pickCopy(copy,"lbl_emotion", DEFAULT_COPY.lbl_emotion))}</label>
        <select name="emotion">
          ${["Айдас","Уур","Гуниг","Ичгүүр","Тодорхойгүй"].map(x => option(x, st.emotion)).join("")}
        </select>
      </div>
    </div>
  `;
}

function navButtons(cur, copy) {
  return `
    <div class="row" style="margin-top:12px; gap:10px">
      ${cur>1 ? `<button class="secondary" name="nav" value="back" type="submit">${esc(pickCopy(copy,"btn_back", DEFAULT_COPY.btn_back))}</button>` : ``}
      ${cur<4 ? `<button id="primaryNavBtn" name="nav" value="next" type="submit">${esc(pickCopy(copy,"btn_next", DEFAULT_COPY.btn_next))}</button>` : `<button id="primaryNavBtn" name="nav" value="complete" type="submit">${esc(pickCopy(copy,"btn_complete", DEFAULT_COPY.btn_complete))}</button>`}
    </div>
    <div style="margin-top:10px">
        <button class="secondary" type="submit" formaction="/back_s5" formmethod="POST">${esc(pickCopy(copy,"btn_back_journal", DEFAULT_COPY.btn_back_journal))}</button>
      </div>
  `;
}

function phaseBody(cur, st, copy) {
  if (cur === 1) return phase1(st, copy);
  if (cur === 2) return phase2(st, copy);
  if (cur === 3) return phase3(st, copy);
  return phase4(st, copy);
}

function renderScreen5({ st, cur, errHtml, copy }) {
  const safeErr = errHtml ? `<div class="error">${errHtml}</div>` : "";
  const c = copy || DEFAULT_COPY;
  const smallRulesTitle = pickCopy(c, "small_rules_title", DEFAULT_COPY.small_rules_title);
  const smallRulesBody = pickCopy(c, "small_rules_body", DEFAULT_COPY.small_rules_body);
  const timerHint = pickCopy(c, "timer_hint", DEFAULT_COPY.timer_hint);
  const hidden = `
    <input type="hidden" name="curStep" value="${esc(cur)}" />
  `;

  return `
    <div class="card integration">
      <h2>Integration</h2>
      ${safetyNote(c)}
      ${headerKpis(cur, st.emotion)}
      <div class="small callout therapy-box" style="margin-top:10px; padding:12px; border-radius:12px;">
        <div style="font-weight:700; font-size:15px; margin-bottom:8px" data-copy="small_rules_title">${esc(smallRulesTitle)}</div>
        <div class="muted" data-copy="small_rules_body">${esc(smallRulesBody)}</div>
      </div>
      ${safeErr}

      <form method="POST" action="/s5" style="margin-top:10px">
        ${cur===1 ? emotionPicker(st, copy) : `<input type="hidden" name="emotion" value="${esc(st.emotion)}" />`}
        ${phaseBody(cur, st, c)}
        ${hidden}
        <div class="row" style="margin-top:12px; align-items:center; justify-content:space-between; gap:12px">
          <div class="small muted" data-copy="timer_hint">${esc(timerHint)}</div>
          <div class="kpi" id="intTimer" style="min-width:92px; text-align:center">01:00</div>
        </div>
        ${navButtons(cur, copy)}
<script>
  (function(){
    const rel = document.querySelector('select[name="p3_release"]');
    const loc = document.querySelector('select[name="p3_releaseLocation"]');
    if (!rel || !loc) return;
    function sync(){
      const isYes = (rel.value === "Тийм");
      loc.disabled = !isYes;
      if (!isYes) loc.value = "";
    }
    rel.addEventListener('change', sync);
    sync();
  })();

  (function(){
    // 1-minute timer per integration step; disables primary Next/Complete until finished.
    const step = ${cur};
    const DURATION = 60; // seconds
    const btn = document.getElementById('primaryNavBtn');
    const box = document.getElementById('intTimer');
    if (!btn || !box) return;

    // Integration timer session
    const now = Date.now();
    let runId = sessionStorage.getItem('int_run_id') || '';
    const active = sessionStorage.getItem('int_active') === '1';

    // Create a fresh run id when starting a new Integration session.
    // We keep the same run id while the user is inside Screen 5 so refresh doesn't reset progress.
    if (!active || !runId) {
      runId = String(now) + '_' + Math.random().toString(16).slice(2);
      sessionStorage.setItem('int_run_id', runId);
      sessionStorage.setItem('int_active', '1');
    }

    const key = 'int_timer_' + runId + '_step_' + step;
    let startedAt = Number(sessionStorage.getItem(key) || '0');

    if (!startedAt || !Number.isFinite(startedAt)) {
      startedAt = now;
      sessionStorage.setItem(key, String(startedAt));
    }

    // Initialize UI state
    box.textContent = '01:00';
    btn.disabled = true;
    btn.classList.add('disabled');

    function fmt(sec){
      const s = Math.max(0, Math.floor(sec));
      const m = Math.floor(s / 60);
      const r = s % 60;
      const mm = String(m).padStart(2,'0');
      const rr = String(r).padStart(2,'0');
      return mm + ':' + rr;
    }

    function tick(){
      const elapsed = (Date.now() - startedAt) / 1000;
      const left = DURATION - elapsed;
      if (left <= 0){
        box.textContent = '00:00';
        btn.disabled = false;
        btn.classList.remove('disabled');
        return;
      }
      box.textContent = fmt(left);
      btn.disabled = true;
      btn.classList.add('disabled');
      requestAnimationFrame(() => setTimeout(tick, 250));
    }

    
    // Reset Integration timer session when leaving Screen 5 (Back to Journal) or finishing.
    function resetIntegrationTimerSession(){
      sessionStorage.removeItem('int_active');
      sessionStorage.removeItem('int_run_id');
    }

    document.addEventListener('click', (e) => {
      const t = e.target;
      if (t && t.id === 'backToJournalBtn') resetIntegrationTimerSession();
    }, true);

    document.addEventListener('submit', (e) => {
      // If user finishes Integration (Phase 4), clear session so next run starts fresh.
      const ae = document.activeElement;
      if (ae && ae.id === 'primaryNavBtn' && (ae.textContent || '').includes('Дуусгах')) {
        resetIntegrationTimerSession();
      }
    }, true);

tick();
  })();

</script>
      </form>
    </div>
  `;
}

module.exports = { renderScreen5, DEFAULT_COPY };
