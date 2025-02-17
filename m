Return-Path: <kasan-dev+bncBDW2JDUY5AORBSEOZ26QMGQESNFUCVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 284AAA38BCC
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Feb 2025 20:00:27 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-4393535043bsf27165485e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Feb 2025 11:00:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739818826; cv=pass;
        d=google.com; s=arc-20240605;
        b=iwvmEvBpaW4rU/1V2xhSG+iU/5lTTlZ3Qk7JNrjdKnKcMI0VfnuS8nfk08n+Lq42dx
         tzeitAlXwrcoCqpgf7hVP3BU4pQZso8uKWW+M7XOr407njVhU4dcnx1/Ps1wb2MfzZyV
         TEiO+XLsnkZ8SMZZd9kt8x2qBazhiE7iruHYUdCFh2GAFCDvYTqs7GkkJ1nIenFwlH3B
         vxxadZuoBoEeC4tPEvsqKPjcj8XLXW9hNx1eLHSZQzczhtlLD3/Zcni5NeyE80tUguNy
         65oXL02RSOHQrCGlmUKSpH1yUTxZqbVzt+AkEGYokL7+Dci1eNT8Ohlua4Lb+2jKsu21
         RUDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=PgW04gseCpLPBXZCOadDlyDmzq2rFfyQScVpnf1Og8I=;
        fh=WAWH29N/FB+BcVVFe8g63LHuUamthwizLRXdhLgH3vQ=;
        b=XVEzEH2FuqsUUYElwGkWs0aBd1EeAFDVmmIN8OroMUHHXtXnhs3ILyhl1p4bf+5xw4
         6v/1mvdgs2jPNrCpsm+ei6HhX6Tmr6dLUKJEJunx+xZCrRaVCjxF3vYvZHuN3Got1TLL
         9rscF0/VgGIcl67mqSXD9f46KkH0m5WgJdERSH6NWAoentC9RtZBV+Y9LE9l98JoKSgE
         apEsVvi+dgn8sYPkWy3JzoieurRoOBjpUqtiheZwKkoJhfH4/ENgfRS3dzhgyDcAKGfS
         25uauVfRiQQiEk4s/ux5aU120+C74UPXYnUgqKaiCv09mUSkHZcPfQt5+575PSmx277b
         MHmQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=fLslrBkq;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739818826; x=1740423626; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=PgW04gseCpLPBXZCOadDlyDmzq2rFfyQScVpnf1Og8I=;
        b=DGjWy26R0M0jV59c0em2pgp7uYbHlgSjLTe5xTtFXqZcA52oIFr/pvJWSJycqUDopW
         EkhOTL7ipxMQa6MbhdhJN1+nXmL8KdZwfxmmfjhIoxhAAKV4DNNTr7oyCCjI/sSvwoAK
         Ef7174tBOwwatSCS6a+8dPzybcOh1qOZlSHrgMWPW/Zxnni3HuL6QyG+QDWZ5r51lpQT
         Yjq4QldxwRSMphyQ5FZN5czyt3SA53AFeskiYnbtld4azwbPRF4kJIWtMjZSwZnb9PRS
         1sFEU9tVFNEDWHX4l5YslQl8m4UycyL1R2zxH8nuarM4XWq2K2SaKS2oe+BP7uqWRNjo
         Nwbg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1739818826; x=1740423626; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=PgW04gseCpLPBXZCOadDlyDmzq2rFfyQScVpnf1Og8I=;
        b=CeDZpqYVFNraeS8aghdO3r/hlTTUIbglb5SJ0JDbAXnS9bS/vDBnxUycD3UHxk+5+u
         fgMyKSEd2sbXscs7D4hWUTzdqrHxelgXsNn4WS48KBQ4iEIT4PYz4LkBHa8zndwQ9Xc+
         FNLT0U5K0P112m4S1zsta0x/4lxPIIye+KX0yz0vtZyI5GylDRMJKjBzmT3s68nL2+nK
         JrhOREg2hX1gUhCXTi710cuSdH5mxVOtVnM8WeH/4zn8br/8+33dPJMKpTUDjlDko+/S
         ESiI8LKL8si/xpdNNW6tuIAVEcjRTrzjd2jCDH5iATe1MLSj6segU3jgHz9iJA6ttk4P
         1sAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739818826; x=1740423626;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=PgW04gseCpLPBXZCOadDlyDmzq2rFfyQScVpnf1Og8I=;
        b=acYSb8yKtZ5EUo6DSAF/dgtZlFn/dNcZ61/MMof8Muxxrfq5zXMJk+fTPDnEqdd/OF
         b4XlONbjFp8Y6peN0Kq5tHldeboGEhu0okLLyWOrQOrHi/D8zPz4f49dXYUzKCY3JwDR
         XcsHewChh3Frv8FMdwbO3SOmwnGGks9cf44cNSk7ScjeqA/ojia4aLG5pdvpRM/1lCgy
         jeOLkjfu7KAdAs2amJ4ylTuz+xhCOeKioD/ziY3KTmh1FnxaRkqpuqKuO3bpdc/aj45M
         iQT9ujzlOV/v7Jay5phg9AaVCrMQeesQmqraqBvr+JJFjNDPTQQF8o5edOEiL0oWhITh
         1mrA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXqG/JnZ80u20a/wxYwNaAGLalmXgzN4FxSLuIVGCpx4Xm0HQU2mntaklZZvLx8omFSroCcoA==@lfdr.de
X-Gm-Message-State: AOJu0YzKDHnHjYVwRnn5jYMZ46WAiwx6+KNU7TZSLIUHmswOOpfmSupe
	/OqTmxzgsNoZ2We5wlHXN9IGQf/4j6JvpQeWbri8d5kSntaoXt3D
X-Google-Smtp-Source: AGHT+IFw8kRlvcg7cc7yEqsrXlW6Ff95njl0u6nJxCpWamMHb436rTePzXNsK20HgJ/eBNIUZTohMA==
X-Received: by 2002:a05:600c:3396:b0:439:8439:de7e with SMTP id 5b1f17b1804b1-4398439dfdamr44986275e9.15.1739818825090;
        Mon, 17 Feb 2025 11:00:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVG7CMN2DEnnGKyp0OFMNWa7j+yGNUKD7F0dHwqKeOtsqA==
Received: by 2002:a05:600c:4212:b0:439:806f:c2dc with SMTP id
 5b1f17b1804b1-439806fc3bfls3769835e9.1.-pod-prod-00-eu-canary; Mon, 17 Feb
 2025 11:00:23 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUKpDibVvp0Wha6cvaysmrAWnz25f+VQJtbEbhvfZvzhHy/UNbCWr/lWQ9asbfjcpooO3CdWK6v0OM=@googlegroups.com
X-Received: by 2002:a05:600c:1c83:b0:439:5736:454d with SMTP id 5b1f17b1804b1-4396ec08d97mr94190375e9.1.1739818822928;
        Mon, 17 Feb 2025 11:00:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739818822; cv=none;
        d=google.com; s=arc-20240605;
        b=hA5ySxHbX1QwC2ekGtBc/Ch+LaGJHhc2D52IA13UtkW+A0PM4yQbrBDiH0xumC5FGN
         vCLEQeReQef32XRY13wB/yykla4268LT8y7wU4/fIsrk2eO6dMjTGUHcAi1eKj8ez4eh
         chMfz2DspRJf67hpA/NP443rtk7h88ZmE53h2Umulc5YeNj80W9hsp70qVjAAarseMM8
         jzMXnIm6Zv8oCZnIf5Us+GefwXZE/C0Etk5yQGc0GqBS4Rw6AFCTHkbVYXEPFfvIl/JC
         ozKIrarZYxyWqItTnIDMcYf7xN20KTftJj6Pt+xoIX+CpgMup9I5fr7h2lnMjtDFljLw
         bSvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=FbEfh1V/TCyzyVBnzOPjw0bmm27Qjtw3b9033vGjqT8=;
        fh=o4ub9qIG0espldcmlANLFTYQTDMjyN8+F3feFiEEJ0s=;
        b=VuJ4ADHz9FN/mINaspYzkARiLhMal6D/FHFPDmKHRmK7z5cPXwk++hxLblYEb5xb+b
         IB4oTqu1jJf7KqomkTRYnLzGm0CqEHRGfTTyO2wjYZxV/TFK/KbDNBEtu2DvMTA3WvaP
         FvQ8qhNCWAhtZK2jlu3+ovibMfGwqVG9BXIDKXIt6vsqUujzk9CoHqKVmMzvDgWoIovI
         +dEjGIBbnkGA71Pxcu46XD3Y8Z6TZbJ4OB/gIklxfs5gELbkdn614xTJrZz4d8J/IFow
         YMlO+goyTBOvPYGm635bIEUQ2oN5itiQIWG2KofZ3GEX+0v3TTQGyZiQqA0/7wBpAfCK
         JV6A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=fLslrBkq;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42d.google.com (mail-wr1-x42d.google.com. [2a00:1450:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-38f2594bb55si132169f8f.8.2025.02.17.11.00.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 Feb 2025 11:00:22 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) client-ip=2a00:1450:4864:20::42d;
Received: by mail-wr1-x42d.google.com with SMTP id ffacd0b85a97d-38f2c4382d1so1887586f8f.0
        for <kasan-dev@googlegroups.com>; Mon, 17 Feb 2025 11:00:22 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWXOZxLTNA0W6kATEfE+DmhA5m/oItjsUwjJd7V4s0HbUm+YcZ/QgtePB9HLCuYpX5XRHVDpRZmv3U=@googlegroups.com
X-Gm-Gg: ASbGnct+MXnS20Q4k/LZxL4XmcJzE/0nrzBdMLMOkzuF/nGsy5J/q/Ir+sLAqtFtMQx
	+xxgY+OfvF/bNi+wHKI2gVC0SyWlKUnJ6k30CGw7Ps6IPEgvqwMz/Am6YOP/me7ixj6fvlXI7TS
	k=
X-Received: by 2002:a5d:6d81:0:b0:38f:2c10:da1e with SMTP id
 ffacd0b85a97d-38f33c288cfmr8157628f8f.27.1739818822023; Mon, 17 Feb 2025
 11:00:22 -0800 (PST)
MIME-Version: 1.0
References: <CA+fCnZeBEe3VWm=VfYvG-f4eh2jAFP-p4Xn4SLEeFCGTudVuEw@mail.gmail.com>
 <e7t5yzfw3dq5stp5xjy5yclcx6ikne4vwz7d6w2ukfw2b7gr6t@oomoynf3b2jl>
 <zjuvfdbl7q76ahdxk3lrgaznk7vjj43f5ftzfgrnca6dqtcd5x@5qj24womzgyq>
 <CA+fCnZfySpeRy0FCFidLdUUeqp97eBdjAqQyYPpz1WxYwcsW9A@mail.gmail.com>
 <aqhm7lc57srsfuff3bceb3dcmsdyxksb7t6bgwbqi54ppevpoh@apolj3nteaz6>
 <CA+fCnZdjTkreTcoo+J8wMhwDuAFM4g33U5BFy0OPtE0UCvyJbQ@mail.gmail.com>
 <CA+fCnZcoVdfXVN8VBFLx835cV0eGAT6Ewror2whLW761JnHjNQ@mail.gmail.com>
 <sjownmnyf4ygi5rtbedan6oauzvyk2d7xcummo5rykiryrpcrt@kasomz5imkkm>
 <tuwambkzk6ca5mpni7ev5hvr47dkbk6ru3vikplx67hyvqj2sw@rugqv7vhikxb>
 <CA+fCnZcHnWr0++8omB5ju8E3uSK+s+JOFZ3=UqgtVEcBzrm2Lg@mail.gmail.com> <kmibbbrtlwds6td64hloau7pf3smqth4wff33soebvujohsvli@kni5dtvpwsxf>
In-Reply-To: <kmibbbrtlwds6td64hloau7pf3smqth4wff33soebvujohsvli@kni5dtvpwsxf>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 17 Feb 2025 20:00:10 +0100
X-Gm-Features: AWEUYZlRIhjmXsKyPCZOszIx8_jhLBbTZLCGYgAeVzNSeJCRFZ5-FeRBt2Jwp0w
Message-ID: <CA+fCnZfBsQd=nJVu7QOX09w6uR5LK1Gc5UqiHS8aCxzhDJsssA@mail.gmail.com>
Subject: Re: [PATCH v2 1/9] kasan: sw_tags: Use arithmetic shift for shadow computation
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: Samuel Holland <samuel.holland@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	linux-riscv@lists.infradead.org, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	llvm@lists.linux.dev, Catalin Marinas <catalin.marinas@arm.com>, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	Alexandre Ghiti <alexghiti@rivosinc.com>, Will Deacon <will@kernel.org>, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	linux-arm-kernel@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=fLslrBkq;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

On Mon, Feb 17, 2025 at 7:38=E2=80=AFPM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> >I'm a bit lost with these calculations at this point. Please send the
> >full patch, including the new values for KASAN_SHADOW_OFFSET (do I
> >understand correctly that you want to change them?). It'll be easier
> >to look at the code.
>
> Sorry, this thread became a little bit confusing. No, I think the
> KASAN_SHADOW_OFFSET values are fine. I just wanted to embrace the idea of
> overflow for the purpose of the check in kasan_non_canonical_hook().
>
> But I'll put down my train of thought about the overflow + calculations i=
n the
> patch message.
>
> >
> >Feel free to send this patch separately from the rest of the series,
> >so that we can finalize it first.
>
> I have the x86 tag-based series basically ready (just need to re-read it)=
 so I
> think I can send it as whole with this patch and 3 others from this serie=
s.

Sounds good!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZfBsQd%3DnJVu7QOX09w6uR5LK1Gc5UqiHS8aCxzhDJsssA%40mail.gmail.com.
