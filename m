Return-Path: <kasan-dev+bncBCCMH5WKTMGRBTN3USWQMGQEV4DTKIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id E8173831966
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Jan 2024 13:47:10 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-1d707a3d254sf1226265ad.0
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Jan 2024 04:47:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705582029; cv=pass;
        d=google.com; s=arc-20160816;
        b=YAivChw3ejKCFkjwn/Kk2x30FoN0k2vnw92mGGM4e1BTUSy1oJmKOVd0uQrZr7297a
         NF8+pTv1c2LtjV7DyHiqgriyNXtnh8zrJKE28qTbLa6kaCCk42p9X0RJkoI51gyW1GNk
         p+vyRAjSU/l7BnR21fB8yHrFou2pxDSRQrCx1PH/KSugrwXm/36sAHt6ZQuIKRtrEb7G
         ncJ231ELfhbtWJdsUtD2jggJlWsnWcjYBU2Gb40xGcE372zR9/ChK1D6S0AIbo6PF1li
         FFJYlw2o/sqS8dRrWC3EmaxDkMPgP5FVdsuCqW2W5YvAgKqDQPBWinG0t51UDEKU8ZJv
         W5Vg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BvnNA1pV9kPAFCpHVngIAVKvLQrjsPRF3IKlxkA4FZA=;
        fh=GzlALEyF9NLgSpM9tzsGNgDMvY8hPgccqiIbi0fjo98=;
        b=LoF3Qu8PARIWV90hLucsH/ic7EKsQ8ZRG8GR91fnBLsF+vJt0w3vpL+wOBLuYgXTp6
         agaIWkvGOcvJrPiEM3f7qpT/9oJYiCmbv5Fnq42Ai6ZH670LXGYKJOR2fyNaIiUCcdXV
         yvC3G0wophygdys5uiw4jQN+1M9+6670psvg1qeI6IUgk8u236uyNgIFQTsTRSxI70n2
         iOuH2hwBWAeGaCE5MBbOUvFivfpdk7qTtGlHlxuDcQsfDZNhr6CJ4xxvGatTbYT2MVOh
         t9szWTwc8/Y2KeTxKgsEvFCH5m5htSN56uzfkUQxZyf6/x7ACk5SPRDTowq5teYd2IMx
         1fUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=qGyQ3x71;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705582029; x=1706186829; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=BvnNA1pV9kPAFCpHVngIAVKvLQrjsPRF3IKlxkA4FZA=;
        b=wj13tokbuXYSupGXtUms14MnglKAMPJEA0unbPSMVYJWM9QpOSOr1wXjAAxRBChd2y
         PBK280fSDEciLQIl746f35KifHxKNVmrZd6qy69MGdDjQl7omkALjR0BfMkC5/L1FvUs
         9w5QK4yHnD40+CP+jUk7MKzkKWzzg0f+DN4lImCYvCknhqAWMWXCewr6C/HILkb4gcH6
         9yWaymHlHfVZJ6pKwXfP06+DC69YbuI/B6J+v8lPpEidruh8Df2ZuXdPEizPoryLthL3
         sFdhfk+8ZmyNARFG1pd060fjJc1NAQt9gCOegdSAhhrNgFBxY2aEUKiX+jraxKhOql0V
         YpsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705582029; x=1706186829;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=BvnNA1pV9kPAFCpHVngIAVKvLQrjsPRF3IKlxkA4FZA=;
        b=Q0oGBkNUuefr/s369ITRHE0VwbVHR7xwK4Jvgocui9q4mK+DrthUiEejC3MHPDMohl
         ZyHSc/Y3zJ6QMIQPi0l3sIuuTFN41dApLIWMVpXtQKWWD74Qm+OsYJamaeJbzL/ZCjWm
         W/JrITqrtoxY8k8apB+cR//ytQyg1BhAh9UxixF651DeLQ8YFVBVLLx3h8VPXMoQeyjh
         3hkDQt97nUUPNH1B6ucXK2rWVLs2LDihFGBoxQ1FkrBODE0FsoBuzlVXL6Li0C47ooNm
         yQ6lcWwW0K2Y9o/kCIHp31zFxwl9MFk3BU6mSPZnKSpdSTAHSGrEPUUWgZ91PrJ/d5xV
         52xg==
X-Gm-Message-State: AOJu0Yz32w4tAVHwXRSzcMgZJX8Zvi5ce7eWO+kjEmI502uTAmNX7bXA
	vHWcuxe0rraCozjvBaQquKrG6XYE0DC1rMveepUo1XgiIQJMV4/F
X-Google-Smtp-Source: AGHT+IGrleW+7vB3v3Yfo52swGYf9w5BEG87pJz1Uy1l8F3va32I40hRcEGAvQ5K5p3Uf1nzVhwi2g==
X-Received: by 2002:a17:902:c44a:b0:1d5:71cd:c6a4 with SMTP id m10-20020a170902c44a00b001d571cdc6a4mr83519plm.2.1705582029312;
        Thu, 18 Jan 2024 04:47:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7402:b0:1d7:583:3d3a with SMTP id
 g2-20020a170902740200b001d705833d3als37846pll.0.-pod-prod-09-us; Thu, 18 Jan
 2024 04:47:08 -0800 (PST)
X-Received: by 2002:a17:903:25d2:b0:1d4:2d8d:3536 with SMTP id jc18-20020a17090325d200b001d42d8d3536mr698685plb.71.1705582028094;
        Thu, 18 Jan 2024 04:47:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705582028; cv=none;
        d=google.com; s=arc-20160816;
        b=FlFpInuANL4b72ovAJk+1zOaX/qnlj5aeEaijVJaEjxwFt2ZHYPMmWjfWe4u+ckbyt
         1/KS8YbC6BySJMMgh53ZcLqVC6GlKii/9i9PGzKVVkCDVCtsUINop65gAODNP26BhoWZ
         WdaytHu21aGecywyMBlbzWFKCBHOhinSDC5CwOR1BqxLloNA2batfM6yuERQ0HgWbkHf
         0/ZRHRGXefmmCYSuhalgOqdYirf0AtvGRUqlUE1QuLexQZ+FaCKGkWN5z7SGsabpzBxA
         hEcoFOmWC8/T7jMbD+zr/FU41kEiG9+eATy5VJOhKJtBZjo63Bs+qz3T8p39MJDT9OuV
         fxeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=7hzv9Q2RyFYsBMK7cp2sHJQU4W1HVKR0nok44qQw548=;
        fh=GzlALEyF9NLgSpM9tzsGNgDMvY8hPgccqiIbi0fjo98=;
        b=Fm+0Yw4rNcIFEIzFuoyLS3+1lCVA/xnHGQ7g53rCx3taW3rLf771yoY9yf5DhqZa1V
         pFGPQ/Tv43radWLLFBI/6DxFDM8ud7T0gLbtNIlZo3nenWD1hCzv9ZEfwC0DiqOHURsK
         ubGIQcKG3Igw6Jrrcol7ItWqnCVLyekYyoO0Mh4n2k160LhlQHnvkeYCEi5G6hrn8jN2
         lIJPinadcauJ56j+7qpjph/PM3q4aZjdAZB+McTKwDOiEjGkO+UARk05OGlEY1BUpbhQ
         guesOv66i1RKsS+oSK8Prbo3597BfIPE1rMWj0qXudvnVQpDH/+VEDDr3m+T+Qk4XPWg
         u1wg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=qGyQ3x71;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72c.google.com (mail-qk1-x72c.google.com. [2607:f8b0:4864:20::72c])
        by gmr-mx.google.com with ESMTPS id t11-20020a170902e1cb00b001d6ecdaded6si112522pla.7.2024.01.18.04.47.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Jan 2024 04:47:08 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72c as permitted sender) client-ip=2607:f8b0:4864:20::72c;
Received: by mail-qk1-x72c.google.com with SMTP id af79cd13be357-783182d4a09so1354645585a.2
        for <kasan-dev@googlegroups.com>; Thu, 18 Jan 2024 04:47:08 -0800 (PST)
X-Received: by 2002:a0c:f2cf:0:b0:681:7867:fbb9 with SMTP id
 c15-20020a0cf2cf000000b006817867fbb9mr747219qvm.88.1705582027089; Thu, 18 Jan
 2024 04:47:07 -0800 (PST)
MIME-Version: 1.0
References: <20240118110022.2538350-1-elver@google.com> <CANpmjNPx0j-x_SDu777gaV1oOFuPmHV3xFfru56UzBXHnZhYLg@mail.gmail.com>
 <cd742d1d-70a3-586b-4bf5-fcfc94c75b4a@quicinc.com>
In-Reply-To: <cd742d1d-70a3-586b-4bf5-fcfc94c75b4a@quicinc.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 18 Jan 2024 13:46:26 +0100
Message-ID: <CAG_fn=VMTOJn+wtg0NfE2bFtuh_OY1DQeMu0KB5u4sjS05sXgw@mail.gmail.com>
Subject: Re: [PATCH] mm, kmsan: fix infinite recursion due to RCU critical section
To: Charan Teja Kalla <quic_charante@quicinc.com>
Cc: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
	Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, syzbot+93a9e8a3dea8d6085e12@syzkaller.appspotmail.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=qGyQ3x71;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72c as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Thu, Jan 18, 2024 at 12:28=E2=80=AFPM Charan Teja Kalla
<quic_charante@quicinc.com> wrote:
>
> May I ask if KMSAN also instruments the access to the memory managed as
> ZONE_DEVICE. You know this is not the RAM and also these pages will
> never be onlined thus also not be available in buddy.

Is there a way to tell whether a memory chunk belongs to ZONE_DEVICE
by its address?
Won't such check involve calling pfn_valid() or a similar function
that would also require synchronization?

In general, if e.g. one can call memset() on ZONE_DEVICE memory, it is
already going to be instrumented by KMSAN.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVMTOJn%2Bwtg0NfE2bFtuh_OY1DQeMu0KB5u4sjS05sXgw%40mail.gm=
ail.com.
