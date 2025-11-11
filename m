Return-Path: <kasan-dev+bncBCCMH5WKTMGRBDP2ZPEAMGQEHP2RASA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 75016C4C8B3
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Nov 2025 10:08:31 +0100 (CET)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-34176460924sf3935380a91.3
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Nov 2025 01:08:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762852109; cv=pass;
        d=google.com; s=arc-20240605;
        b=QYI70m3U5rAjvBz0dI/tMY8GmZtmi4D/jVzhYsgI1HKPGfD5fPHTE3tfEPRNlqChEE
         VKc/3OpyfQbxrr6N6kz/oKejKqT4YF/ijrFmA111rx/hvtFt9I/SejTKQGE71gt2uIa6
         opAodhzJWEBdEnODWxxsi61HG0JrX+pw0FAo/niANHu6Tpglr679dm1CNOgF4kB24xp5
         tt8bT2nbI0JRzEqK0GJMHpqCULRyuqXMqqyX/F1QatffUnEhXwwnK4vY4rCDaRV5DnVL
         uk7pM/Y/5kjwAM5ZeINVVlqrT2UjS8RBeXvHHrCc13TQ4DdrgdhNUkWGLmVZY31kZ8tm
         9WrQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OACgddBsPabC/baquU76LSqX/DSrLd8bJdwzlxJEz9Q=;
        fh=1jGm3oxjJN7k4ZA3ORTDariBGpQLFb1H4ncASQYAI1E=;
        b=Tz+FjDI5CNYO58kO7DtjFAk6guAhDrApl4J+PFpYQ3lFxVZzQ95iGAshPkfqcHaZJd
         SEwmd4FBvlvdkMjF+4i4YfD3MbdjzRsv/AL5/ZrHIsfREUF+u4C4OVECtiAjjRu0kKWo
         l60Ei3tvAytU6djMyn/ArJEhCMO4PQNjrF5u8aYtH6yEcPOc5MOMoyPv2e3iUDJr0S2n
         n6gsOWQBcJS3611mDMC8RG4Fp5S5ro2VqsYEpmIxIULYAELNUygqj7lB/+fjF/T7Oezp
         4bKssxHhz65mxqqqDkVGV/DBVFSgje0ROEUSCZlmrtp0CpQRYWAPp6E8v2n+lxx6ItqN
         Lizw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="1taEm/Tj";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762852109; x=1763456909; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=OACgddBsPabC/baquU76LSqX/DSrLd8bJdwzlxJEz9Q=;
        b=gjoxpDY8iChugMSFY9QEl5DW1bmkqnAoT1Oj1GCz3bvjfxAV3lECP+i2rSm3YcFjHl
         gaFAQbNLkvniL/WypWcMOysracpWV/kIQt6EkwZWTSg2DOE9UY4IRq5Ql0OvUV1cmKZW
         kFNQ+M0kIfX5634PxHhc9uXYmYcqByYksvoR2jO1WatAqHtrVm9hkdpi+3oA+C6NA4pR
         V0PiAY1uvM8YiEwpheByHc7nNNfu/bO3DNADFhF82cgao2kaSEumd46eBVLwvIqG8h2E
         HBkkt9d9zkcOgf9Tkw/EXyRBI/CXOYPenVyWaLKQ81A2DwGoBqCC7x0ZJ+nkiq+1WZeH
         bpDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762852109; x=1763456909;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=OACgddBsPabC/baquU76LSqX/DSrLd8bJdwzlxJEz9Q=;
        b=wjABqpREzDdJsH/367DQCJ/3Z8jP4iHlegfaO21aUgEjCq9WQqImiBQi4N2LZWxDfV
         0XhEUKAw9iipbaCgj2r6E6v/Feyy/4D2lxs4kNTIVXtXhdK2jD3Ma1qwhdy0k4ztvinN
         2j5PLwj6gR9zFx2FXfG2tsBNjmRJkMVNOq65Aj8/KE4oQtVrlIZD+bmZc2/sHquFStnC
         Y6EGFmfQ/scJxY+rNHNYt8y5vIN6ycXDcg0Pvpc9wRmbtIwGs3N90gag0QQ1j9i1yfW9
         5mKRaEh2TszgmkReMM4ElKEushCQJBbGd40Gxc6+UKZbJ7dkIa3+kZXv2LPO9hGcYyJv
         LYQA==
X-Forwarded-Encrypted: i=2; AJvYcCUgjZ87eb9MKmVFx21gy9DHdmY+j6nyJ5aDPTHoJz2aVp07wxNL8yIHyMIYqaprpFgoe0gVHA==@lfdr.de
X-Gm-Message-State: AOJu0Yyv3AMJibMittp3t6ROtGqlL2431qnGXTVI3rqhaunKh9i2Ulhz
	R15kZW0WbUX6VKtGAKD5kuj/umkREeprQ8G1TKgc1wGF3Tw8lpc4HOSJ
X-Google-Smtp-Source: AGHT+IE6DozwIU6COXAH3wqmm00c1ENnlGpiiCgTFJSOw0bX6b0l/0WFxkJsN7QdBRajJDbbQAR4dA==
X-Received: by 2002:a17:90b:1d49:b0:340:be44:dd0b with SMTP id 98e67ed59e1d1-3436cbc6fc3mr13458257a91.34.1762852109470;
        Tue, 11 Nov 2025 01:08:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YO/S2Wgvvl3BZXdFg/3iS44bW2VTjunD+5sTRUcAS/tA=="
Received: by 2002:a17:90a:e214:b0:327:e760:af15 with SMTP id
 98e67ed59e1d1-343641d14dbls1046384a91.0.-pod-prod-04-us; Tue, 11 Nov 2025
 01:08:28 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXTNBB3SHk29Cm09DBivfguPpjzxd6rm+eF74b2yLTblULV3SL1WGrTkUbUHdo1r1BVT/3y5KPYf18=@googlegroups.com
X-Received: by 2002:a17:90b:4c8a:b0:330:bca5:13d9 with SMTP id 98e67ed59e1d1-3436cbb16e0mr13521824a91.32.1762852108068;
        Tue, 11 Nov 2025 01:08:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762852108; cv=none;
        d=google.com; s=arc-20240605;
        b=fHjRSicf9yZhpdJNQm4zCPd5+OSnaBAfjkME6VHNfuVPBjB62MVGVIcn53W+Uskx72
         r2T+eZ9rqZwrd864DMwgf64HU5ccTMYZrE6ztqMK42WZnfm4z6zHf9qm0+rKl/0RrjfB
         GGLuii50NPCchpKMhGXlcFSkPs3O4d40KsoRaeRyuXqsfRhgSx8fOMu7r4pP1lUXlrJ1
         vGL55FuSrEzw/IGBZs457X7+IEuMw0pSjc1gKncE38+J2sLQQNrrMi7HUC15B5B963Nl
         8J/i2qCV6O7FGvBT76pPFC7Ps4szX5iEVTKrWv5+BozU4VdL5ihDqamZfzbnhaOuPtvm
         2vNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=T+mH9+7PNLYr6Z/2ln9TuMbRS+qcoVyhy39YsWeg6dI=;
        fh=utg+lUNeOHM7tCyET1ofDoT9p/pSSV5MtW9S88N0D3w=;
        b=EnHL9mUNEBTPkT2nAGF0P1jfSYYafHhDPXb9SwY3LzP7uA6iLW+Xmkn0rCb9vYSajU
         zA/Yedn8dY0Eulm/h1OHY+nOHvcY6DrypDGWAFFertZF12m7WkbVsmuTvIIW2bBmT7f5
         XZzAYiMspomXpGbR9f7fxlXslfdupnAlmIh5YsHQD0yXup1hzlLcRuV87hhavDROPlrd
         f7SrpVpWXbs/K0Hg7xb6RpK0FgX7ciKE5QkFZYRzc45Na4kqKTZrRMFbfFdgBMOyw/0d
         XmCbfmt/OjrTxRv2lRbP/zLgHQltNbZkvkjP7p5wOzyM6Dj1XvVJOQz3h/lIVAqgHfft
         Rr+g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="1taEm/Tj";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2e.google.com (mail-qv1-xf2e.google.com. [2607:f8b0:4864:20::f2e])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-343861107f7si53775a91.2.2025.11.11.01.08.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Nov 2025 01:08:28 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2e as permitted sender) client-ip=2607:f8b0:4864:20::f2e;
Received: by mail-qv1-xf2e.google.com with SMTP id 6a1803df08f44-8826b83e405so299286d6.0
        for <kasan-dev@googlegroups.com>; Tue, 11 Nov 2025 01:08:28 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXWCvo/8Po4KljmkcYCodQS4OAW2HXO/1jCaMQ2Lnj8OBsVWs9+Ir5vUHNCsMfLc4pBD0UbYZ2AGZU=@googlegroups.com
X-Gm-Gg: ASbGnctJkrHFIe1QV3OMPE7HlQBBYURERDmjjDABUigE4IL5rd7aXpTm00WIl5iVWW0
	oORZK61sO99YO+0lKpEOqT7HjHKoD6iNeZjgkv8PoWdSrmDzib2sLasH0Laucglz4uOl9mxQ9hx
	k7rtqX3kbvffmRtyaaTZQx0eKxdzyQbTCL9oWyPEf/NhSWNhWKzh/zxDhv19a97EY/1qdkm1doL
	m4wSHprU5hoUYojk+ET7jeYv9Ur+Qa6fW7zPTzA6jQcQUFliLc4nYBPftRgsSoXrbfc2C68SdqJ
	2CDbpgEttX8ElxC+YaphN7xhjE+9E+h/T881
X-Received: by 2002:ac8:5751:0:b0:4ec:f4be:6b12 with SMTP id
 d75a77b69052e-4eda4fd3621mr141844221cf.72.1762852106635; Tue, 11 Nov 2025
 01:08:26 -0800 (PST)
MIME-Version: 1.0
References: <cover.1761763681.git.m.wieczorretman@pm.me> <56d9203b1fcb6281b0d29b44bc181530e5c72327.1761763681.git.m.wieczorretman@pm.me>
In-Reply-To: <56d9203b1fcb6281b0d29b44bc181530e5c72327.1761763681.git.m.wieczorretman@pm.me>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 11 Nov 2025 10:07:50 +0100
X-Gm-Features: AWmQ_bksKNIR8oRrvQW5ElnBBjqadCFUKWpQKwYmKonXZ13JEF-XHOSa5ehktsY
Message-ID: <CAG_fn=U3SLOoy_K-2ShOMYf80i4AE1tB1AL4w7wcJAXBxi+PtA@mail.gmail.com>
Subject: Re: [PATCH v6 12/18] x86/mm: LAM compatible non-canonical definition
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, 
	kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, 
	ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, 
	morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, 
	baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, 
	wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, 
	fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, 
	ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, 
	brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com, 
	mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, 
	thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, 
	jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, 
	mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, 
	vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com, 
	ardb@kernel.org, Liam.Howlett@oracle.com, nicolas.schier@linux.dev, 
	ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, 
	broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, 
	maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, 
	rppt@kernel.org, will@kernel.org, luto@kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
	x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, 
	llvm@lists.linux.dev, linux-doc@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="1taEm/Tj";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2e as
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

On Wed, Oct 29, 2025 at 9:08=E2=80=AFPM Maciej Wieczor-Retman
<m.wieczorretman@pm.me> wrote:
>
> From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>
> For an address to be canonical it has to have its top bits equal to each
> other. The number of bits depends on the paging level and whether
> they're supposed to be ones or zeroes depends on whether the address
> points to kernel or user space.
>
> With Linear Address Masking (LAM) enabled, the definition of linear
> address canonicality is modified. Not all of the previously required
> bits need to be equal, only the first and last from the previously equal
> bitmask. So for example a 5-level paging kernel address needs to have
> bits [63] and [56] set.
>
> Change the canonical checking function to use bit masks instead of bit
> shifts.
>
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Acked-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DU3SLOoy_K-2ShOMYf80i4AE1tB1AL4w7wcJAXBxi%2BPtA%40mail.gmail.com.
