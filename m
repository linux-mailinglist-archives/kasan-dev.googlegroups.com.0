Return-Path: <kasan-dev+bncBCCMH5WKTMGRBG4ZZTEAMGQEKOSKAJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3461CC4CF18
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Nov 2025 11:14:53 +0100 (CET)
Received: by mail-oi1-x23c.google.com with SMTP id 5614622812f47-45015d0d16asf5274266b6e.2
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Nov 2025 02:14:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762856092; cv=pass;
        d=google.com; s=arc-20240605;
        b=HR7pJK4pSpLayYusw6N+8LzyBVOgdnattaxjEj++e24F8sBKEwmUMlZHZgds60bzy8
         PK4MyHpK3PT7pQs8bF5d0NMQo3n1/hs7L/OZ983bpFqId4cFRAx74Pb1ediLESRV5N4C
         13ffu7ec3Qqi1hLOdHWIK2+TWsllNELZLUPKLP5T9rwFQmR1s2cqTE0CQHQg1eUPXxqx
         5qeQI8jJviwChefkCxXFZscACKH609sTirwxhljnwo8Fk7uUMqEdK5Z3iHKs/K7Ss/nz
         1YKnSdNBJaPsX1KIKqChGzIoYV2z9tVOx375gWsXKRQcuL3onKu3rbobnPwPgmRzpaXg
         WEFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=OhaGhEmWDBCdrD2fwt5G+WVXeT8qb40cseL5w3GQsYg=;
        fh=nhePkNNd53Xu0eDoCdZzxkxBugOaSzY/rGJ2tIvbDbc=;
        b=OVdcAUF0he4RabAGVNIbGCkP92LWdOFPc9kTEC2xHvfaILxgwJYmRQwcsRiZsiDgsr
         bYEVK9UN2Rqrw2bQ8OohGMzkR8KkVKRroOl87R8a8mxPd7Q5zD5QyQ7+yPePwV27S/Oy
         5iZPr/GFOgdlk9dqSnzO4v+ON10YxcCIU/dtQsT5dXUx/o/fbwGYZZPiEhgtAO6hstvR
         QK9Bd4tuFI7lOnQoAqgy/8Crcg6LEk5dU5I9XdAa+Mz9jWPwOs9wpuO3/xOlDX1nbIPb
         UsVOmqp15UafN7Dri8+kcAfU14UNkAUrq4sQ9wsx/CIozfQdJw85E5ejZI5or12WD4K4
         lKdQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=aj39otu+;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762856092; x=1763460892; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=OhaGhEmWDBCdrD2fwt5G+WVXeT8qb40cseL5w3GQsYg=;
        b=Zh2VKfL2QqJKwfL+v0re3SDIiaAoe7hJBt5O/gTX4MzEzc+99i1kxrCTVtiD5sk0do
         OuGWp1Ue3b0XVOnY7zDe9uXSIMdZHUQ4aNZ1831iiY6FkdwDjQKnwqAvQt/RkHFV6ik8
         E79p/jH11Dw/C5GRkzZFm+oFkcYVxFxgo4xHWFzAY8ZPMFf7axIzdqR4CPE7/Yluv/qj
         AwHXPYls2DkgnUgNPMm+J/xOaJP84G2jgdbCOEXt+fTscW6I6cN3K6sVB3uQ5BZJ7Lh+
         iYSdhG+UbRumhIQl04MhlOzCgxWSRw+ED+1+ZNbr5twyImTdr6we9go8B/GyhtuGL42B
         k3pg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762856092; x=1763460892;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OhaGhEmWDBCdrD2fwt5G+WVXeT8qb40cseL5w3GQsYg=;
        b=fWvcoLjETUFLFHEUpUQK2SXDk/eEl5BeO0mkh6odXyphEZoQtqWdhKvd2ZgXwOUwLa
         gga/CCXLkS75d9I4BrKrPj9KxSQexwJ3HNkYW2YQMJfg85T9ozQMSEQpJ6gIgYzdIHTv
         P5N7SInPeeWkRDF15o9NOJ7lughfi3FxYi/bi5ScC4Fm6tiDMDKb/sqmz6TXa3PjiD8T
         rA44t1ttGQmvuYixRjsR5hNrBiEqKN3Vp+91n/Fp5je3WB46TZr+kpFASMWBIk9J3cGY
         f66qfS+E5F5PJYd27klDtpfzn3xdb+a+TSTB/GNkXRT3u25PtDR8baq1xb6X9B4mC+DJ
         bbWA==
X-Forwarded-Encrypted: i=2; AJvYcCUkk2t4Cym0rLWg9H3ZwkyeZ8GQ9+tw6VuYAnSMBVgbg8+jj5FpCVqX51AuqfTnsAcfhYE15w==@lfdr.de
X-Gm-Message-State: AOJu0YzbYsDLiOxSd8p7D/aOQSn+S1404VltmPDsfq26CHfS+2hRZlKo
	ggcs/avkb06P6e2RM0Aqwb6919ledqLSnSJ9dMIRbCvCyWB37T9o2EZT
X-Google-Smtp-Source: AGHT+IH2hoAi4YG0vbLuo24md82yiDcxKysrs5k6l9dXIWiqThEJTeV1mPLt2HmakgD3NhdG1C/zcQ==
X-Received: by 2002:a05:6808:6f93:b0:441:8f74:e8b with SMTP id 5614622812f47-4502a3f6beemr5277681b6e.53.1762856091883;
        Tue, 11 Nov 2025 02:14:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YQklDL5PIN6Tqt5nSO4AIOMjnFrtLJih3sG96jXCRzhA=="
Received: by 2002:a05:6820:1954:b0:656:dc35:4828 with SMTP id
 006d021491bc7-656dc354923ls1209307eaf.2.-pod-prod-07-us; Tue, 11 Nov 2025
 02:14:51 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVS31sJxypxlqhM060VmyrY5x6n8XqO1I8OwgHikqgSBHCtNUqVDfgHaloEO23poNmZARip0uTCSOk=@googlegroups.com
X-Received: by 2002:a05:6830:4127:b0:7c7:178:abfb with SMTP id 46e09a7af769-7c70178ad7dmr7515900a34.12.1762856090929;
        Tue, 11 Nov 2025 02:14:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762856090; cv=none;
        d=google.com; s=arc-20240605;
        b=IsXSh1qzlifvGq7pN95QWhb3pfzbW9o9Rrg7LU1DZiSoWrS6n+odlMLjFkF4FVyhCl
         17qXOKvXRIGHElCdM1DKN3lbOb7xXEhvTkKcB/D85uLNOxrTEFn4VPyfvIS1wCUsYS6w
         7a+r35LQuLYPg4WR/010kcFj7bhbGC3612/CVDU8O333zTV8JzhDm81tSP46PO0ERsfc
         sx0XL0FsC/qo9GUmCUe9qeiVmY5k0gZZTmoFGs+wtJhv5HHlUKRpQBLl4cxS3M8CzXKq
         Ta3YWgq+REVzant8bL8v20lQgsEffMnpI24m2Trl7siOGdLwD0JvFdNbtF/MIa+gUydK
         5XfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QCoNa0bAFU4qkhO5GhIkfapiatY4Py/cCoDedmB34wk=;
        fh=nc436KBM7PgD7G3pGRHH9KHQ5IMpQDlNtDgOK8PDOLM=;
        b=iF7WsdyS7k7or/iS/4W4gQYCvJFP1btwd5G3K9VQmx9SgJukEQan34a4iTz7mtbpDn
         mn5zjK27a6qCBweSJ4OMCso47e5/tDOqSHMrKA0+xjLK9PkG/F6y9zqUCTz5Tiwurc3y
         Y0CjHKci9QpkB0toEh05l0nzpH26BnKjyQq/VmXvZmb0XhOi9cmAHHZ5Ye22Qn1SDPI7
         GLHAHTCFiEaI//iQDGXLk1KPgsWAI/GvSl/Trd5gtFA/mcsJ6zmbWS7qbVbvn06vIQx1
         AaVs/xlyBBNZwdAfovuvQTRUvS2LHmsfj0l4GMAwXVBWhywjK35cj2rHbWIhibLhrGeb
         MiKw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=aj39otu+;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1030.google.com (mail-pj1-x1030.google.com. [2607:f8b0:4864:20::1030])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7c6f0b182b9si207848a34.0.2025.11.11.02.14.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Nov 2025 02:14:50 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1030 as permitted sender) client-ip=2607:f8b0:4864:20::1030;
Received: by mail-pj1-x1030.google.com with SMTP id 98e67ed59e1d1-34361025290so2773771a91.1
        for <kasan-dev@googlegroups.com>; Tue, 11 Nov 2025 02:14:50 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVel0D3NpHhNQgn63UvFf18kvafjBRtzZIg673MruvhqGAUxUMIknt6zIyn92Kjj5AjuJRT2tBNNu4=@googlegroups.com
X-Gm-Gg: ASbGncveBJIAxG2od1neccczGsO0AmpP9Cbv7tBo+tiHygBoamAlPeQS5sYdSPuK6Zw
	31QZHagSN70voLiOHNL8mT1VO6MNggZRzFZ026VxrYS/tAYAKKtFMFlED07WYmUfhBfOGjGMVLn
	7bUr/pBprBZ7z36BJPEtEZ4O4jmcTG+YPJwiAFTksEP/c9YOtM8cqNcbrvFbHhK1jfE5/G4M2my
	jNVROsAM9GqRSnbULuOKASUMsqGR04IdDwdudyCPDYgAHMx/Mc/5i7Lh+60UhjA8YyERTP1sdLm
	ugDJlLQhNH6ZKslbkDB5BN+gg+hWmBelSKcX
X-Received: by 2002:a17:90b:1f87:b0:340:bb64:c5e with SMTP id
 98e67ed59e1d1-3436cb89ac3mr14436274a91.14.1762856089911; Tue, 11 Nov 2025
 02:14:49 -0800 (PST)
MIME-Version: 1.0
References: <cover.1761763681.git.m.wieczorretman@pm.me> <8b0daaf83752528418bf2dd8d08906c37fa31f69.1761763681.git.m.wieczorretman@pm.me>
In-Reply-To: <8b0daaf83752528418bf2dd8d08906c37fa31f69.1761763681.git.m.wieczorretman@pm.me>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 11 Nov 2025 11:14:12 +0100
X-Gm-Features: AWmQ_bk1ReQnmXZU019ENpKczYWPK1RduG0S2XHhWai-9JyZu-To_X33SgyNVa8
Message-ID: <CAG_fn=UzrdF4v_0iK5b+DHDhFG5pD-W4cac62YYK5x2hgPx9yA@mail.gmail.com>
Subject: Re: [PATCH v6 15/18] x86/kasan: Handle UD1 for inline KASAN reports
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
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=aj39otu+;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1030
 as permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

> +++ b/arch/x86/mm/kasan_inline.c

The name kasan_inline.c is confusing: a reader may imply that this
file is used for CONFIG_KASAN_INLINE, or that it contains inline
functions, while neither is true.
I suggest renaming it into something like kasan_sw_tags.c

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DUzrdF4v_0iK5b%2BDHDhFG5pD-W4cac62YYK5x2hgPx9yA%40mail.gmail.com.
