Return-Path: <kasan-dev+bncBCCMH5WKTMGRBA4KU7EQMGQEFDHVGQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 29CBFC927A6
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Nov 2025 16:51:34 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-297ddb3c707sf15730815ad.2
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Nov 2025 07:51:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764345092; cv=pass;
        d=google.com; s=arc-20240605;
        b=dbHFXMAZFV3TI8OGmFBWOsWB80/kgNztqTmTy/K8oOcRJFgxxhVTQtc/FMMV/H5DVd
         0l7den/B/L3hhiRJZQlIk1tfSfa3Gp9nYOJDFVUejSfgpohvt7WyxVCENzgDSKIv2upk
         h/CMG3oj4NUNXnNBiGRPGJHRihaHUyb8QPE0ClZDmlTyFsareFvdG1nszH/a94n8ZF03
         Vi26vJ02QCM2+09WxYf834doPmQci9iXu9+8FBobJegwlcrFugZpIiPO2WKPu6ToXMh4
         f9q7w1l39e09sHZRc0cTYvalq/j3XRYS41SVbc/Sgt+0inJURRuFLN5tBSJVFf0oNcwx
         ZHNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=6+iOLspKH+G6BgGB+ywYJh/+chU23q7kp7EoKSbMMdc=;
        fh=GPkZdDwtYucrk19yAOhxkE6hvHCD6gIydNzgfxPlXFo=;
        b=QQzO3tEE2AGVvsf8NPdThtWtdUFaWzwTtrK5aloAWrjOg59azDxb7wljVyxXkhEHuN
         NMpyXF8wKdk9h52DF7uQfKSC7CiY/lT2jiokgSVi/EPmL7oPfluWVm14iBouaJKOhdem
         X0yDRf1Og3Am6y6e7Zs9OPM+AkXobF/4PB0UqxfaZjay/XsWJsnwOaSJeXatNdno3ZfV
         Ya1craau5zEepkXe2iIy/eld/5OW+MxALB4fpz5jr9MyywnxM4uJGutBa92MwiZ9w2yq
         ZkUeMEUcZwHMCoAl02sbi/b5zEcCtBGDiCktmWPmC3gztTGUmfoLAXWXLMNcD4yox0g1
         eUZA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MgLzZyVR;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764345092; x=1764949892; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6+iOLspKH+G6BgGB+ywYJh/+chU23q7kp7EoKSbMMdc=;
        b=gNmnP3NSV/HkchvZRqlmlZlKj1B2LtjansF72Azkcbhgb7HQVt9wSM0P1/TzCOsyPO
         sJmS19rn3Gh2nyr8j1n4NB3J74eLWPCargeuZP/xDkLynBTA1YEgvSLw3HnHbwdA4kyZ
         uUkj5juQ4+Yx6aZBfLVw7T3uFl55v/Z4HpiAoYJeA3BxyLKOP/nJQzHE2feL+c+FcqL8
         o94R9jlYKi6G/lyawoDFo9jWD0CsZ3q1iOFXTJed18cZqHNYj9qz7jmFKmRr3o4Zy8qq
         bG9Ds6+5hHWF/HXjW6sZW7O3QvAuqAHAvRVaLvRQ34Z5t+Fp5jAYdQAmK68lJN1RiQNC
         uVDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764345092; x=1764949892;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6+iOLspKH+G6BgGB+ywYJh/+chU23q7kp7EoKSbMMdc=;
        b=jpljNG1mPvnkT9rebcn1Ek6XGIg0GLPU67HeCcAv8ra8JXnR5sucjlGrz0HHlUMofK
         uzSAWHuAVJcaRdF+loUUf6vQBR8DNOvqmU6Vf+XMD3zPfexIBMPridsQNk+4VB/Qy4jQ
         vl0GIeL306fXQxnoOG/PxZVSaHBX3fNjA01+RvRhCgSrlS+ahte9u8bJxbqQi9AaAm3z
         0gV4PHn5PAs+KpyCMWNJ+Sa0iggo1FKd3eikYoRKCcPCm2RwOnUk7ScIstsAxIs7cCZ3
         yVSXv97S0U9riLvNHTdzUDL1smJBA+uDdfaYGqzK7Y44Es8OYtCRuhKDvj9XaW9mXotm
         JfWA==
X-Forwarded-Encrypted: i=2; AJvYcCXEhCALUF4E1QQ+vj5dKaGzq/xUzUwuo1DVVfV/41q+GWs69HJmG1FaJm5k4tD5L1hxIEjfBA==@lfdr.de
X-Gm-Message-State: AOJu0YydkAa47fNV4ddCZKPQ7qFvjVA89rBnlavnrBoAjCf7xIH1YL2V
	SGoWO0aa0z7oLkm3OxOPQYMc3aldYUA7xOuvx78Wo8SfZioqt2ppt1XF
X-Google-Smtp-Source: AGHT+IG5mU6a3lZP77V8DCc7wzlwelbmJ/fme+92eqzvJJGCR49Nlyp69SyjUzijmfHwXuk4U96ioA==
X-Received: by 2002:a17:902:db04:b0:276:d3e:6844 with SMTP id d9443c01a7336-29bab14895amr171704515ad.33.1764345092191;
        Fri, 28 Nov 2025 07:51:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Z75Sq9DGcQH6rRjm7e+6FK5o6GcZjYs5tbr531pbG/EA=="
Received: by 2002:a17:90b:570e:b0:343:ca22:84f6 with SMTP id
 98e67ed59e1d1-34776fc0a48ls1816646a91.0.-pod-prod-07-us; Fri, 28 Nov 2025
 07:51:29 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXWVJJF4zJcy6foFvP9zvt65y/awo/xE6PxQUL5uC2EkCCblhK9VMKY2r9+llrzDUwve75o9pJ7TTI=@googlegroups.com
X-Received: by 2002:a17:90b:2f83:b0:341:194:5e7d with SMTP id 98e67ed59e1d1-3475ed51453mr16173276a91.24.1764345089627;
        Fri, 28 Nov 2025 07:51:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764345089; cv=none;
        d=google.com; s=arc-20240605;
        b=RiiDS4uLh31JfTKqLmYCPkz8l/8RNOEXbMlDmUwW0h23bAbiQ1jeDkt+bAMVIb/88K
         TxTS6y+paHT4QA5d8xL0+wW5iePaYFo6PZ/wimt0FPpQsBu22tJskp3/ZiXebB9Ow1qh
         n+2gsVJPB7szXjViNPxDWPjwkgKkiFGFNfcnZqKnsL+F++68prd+WtLE5H7U4xuPtM2U
         CdSuL0KABdK2vFBuca7j4H2jsLYdMHPB3jFJV2CsPoscuFuiJmh3fNNPcG+l88l0LyDm
         KeMKSuDnxUBNAoDW/GkKzmF1spWATEe/us/viAXyMyQhwo3G5btNet6ScHe23Ny+FR6h
         ADyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ozvegxpQZ76Gmd4MPL9aKvB06f3a0E0RzNh/s6Socck=;
        fh=+KYHi/250VD/4NzVGM461fA/x0LCwEECLWNUxwMWBzc=;
        b=AG8NMaj5Vu0mNwyywKdG8GRXSrP88v450ojTbsYAdOvW/TalLnpKlmT0hVQUQfLvfr
         q8ACxEcCqY5Opuj01bLkgOLuY8ArKheKdDeYg8UQZIsIzYl1boFRRZoxp8k1u8Gk7v6U
         k5vMWC/zg9iVq55JEMvOvsTPKIdg4meIL00SbnRzuOrF5aHbKG6g5i5f5oWwdY6H+6Gq
         y+rxAjyPBmlvoq3/gKsKmn/CaQxNMWhJp0qcIsyxvKJW9eafQ+GSqEvn03Lqx5godEGg
         1S89OBUylX1+qCeKz4/rzYshbCvEoMwKwQMxQ7R1PnQugdBNQaXKgWdTkrola/GjM/gX
         7oZA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MgLzZyVR;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf31.google.com (mail-qv1-xf31.google.com. [2607:f8b0:4864:20::f31])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3475e889f88si124575a91.0.2025.11.28.07.51.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 28 Nov 2025 07:51:29 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) client-ip=2607:f8b0:4864:20::f31;
Received: by mail-qv1-xf31.google.com with SMTP id 6a1803df08f44-880576ebe38so20551106d6.2
        for <kasan-dev@googlegroups.com>; Fri, 28 Nov 2025 07:51:29 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXlP49pxfqkPVsbVu/ulLzKmvdKWL7BaxEnTHyZ97mw4z9SvUPKsruS2RCKF6VGmQOkX/mvAdGGUno=@googlegroups.com
X-Gm-Gg: ASbGncsNIrqrQdyZ/zzpv1KFUE9hZYycO7tj6irkn6+pgus+hEIfnSvJznfuqBuODzT
	lmiu209r5B8+6X0ImuL/sofGBi7k0Dkisq/jTLRDJ2t+ZsCF/tcYH83nizVD/d9ROjc11AJZiya
	qGS1GHxr4j0+N8vmxoK1wNSXm4KQyDPWEXQmnx9CeKAtR5I14NT3NFDWkX/QM86oIc7kW59noN9
	ubgCi/RfSoRoGrq5CCpldKWIWWJOIp28S5MFzIzqUrX9c+aWP356z1spzMjssYw5clBU6X8wpBK
	BkXGzV5ZRloPpdIo28tIwTxTcZMehzg2wX+O
X-Received: by 2002:a05:6214:458c:b0:880:415d:a9ee with SMTP id
 6a1803df08f44-8863ae8a8b3mr216933026d6.26.1764345088423; Fri, 28 Nov 2025
 07:51:28 -0800 (PST)
MIME-Version: 1.0
References: <20251128033320.1349620-1-bhe@redhat.com> <20251128033320.1349620-13-bhe@redhat.com>
In-Reply-To: <20251128033320.1349620-13-bhe@redhat.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 28 Nov 2025 16:50:51 +0100
X-Gm-Features: AWmQ_blrBdFoteeKgRy9ZgZrLR9hCgiNwq7F8c9neFw0fvcV5_-PUj9Uqs2bsZc
Message-ID: <CAG_fn=WpLtVhhOfU3pBKbJ2P3ih+PX4oW+MKAAmHRW0onOgSvg@mail.gmail.com>
Subject: Re: [PATCH v4 12/12] mm/kasan: make kasan=on|off take effect for all
 three modes
To: Baoquan He <bhe@redhat.com>
Cc: linux-mm@kvack.org, ryabinin.a.a@gmail.com, andreyknvl@gmail.com, 
	dvyukov@google.com, vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	kexec@lists.infradead.org, elver@google.com, sj@kernel.org, 
	lorenzo.stoakes@oracle.com, snovitoll@gmail.com, christophe.leroy@csgroup.eu
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=MgLzZyVR;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

> @@ -30,7 +30,7 @@ static inline void kasan_enable(void)
>  /* For architectures that can enable KASAN early, use compile-time check. */
I think the behavior of kasan_enabled() is inconsistent with this comment now.
>  static __always_inline bool kasan_enabled(void)
>  {
> -       return IS_ENABLED(CONFIG_KASAN);
> +       return false;
>  }

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DWpLtVhhOfU3pBKbJ2P3ih%2BPX4oW%2BMKAAmHRW0onOgSvg%40mail.gmail.com.
