Return-Path: <kasan-dev+bncBC7OBJGL2MHBBV7N4OGQMGQEIGIOFZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 98121474C54
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 20:56:07 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id o18-20020a05600c511200b00332fa17a02esf8233873wms.5
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 11:56:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639511767; cv=pass;
        d=google.com; s=arc-20160816;
        b=TOSfL4a3g99aQJrTItzerLVGfEbADR82GnhRjV9uEVGQEwG4DBDpePaCNCYdXuewuX
         xkwMf87p+8YT6uRPl1mp2clrluC6JG7/zGQL8vILxE0VkJrRVFUmZpQ0AlQgWZ4POYUr
         j+4YJ2DF9jm1zSbN0vhld640+E+Kz60mxhS+tFlteQAzh8FMdJsXXMU3tTBHDCUVGr7n
         0FuhyNZDhZmC3r1DdjKpW7xldNK0sU5n1lsY6whcn6XY58FxnvkrNi658SSQDwJzLhpz
         Zw0nv+kSM9JRafnvLf99xGQuXRyD/ll440Vv+jU0ZiUFgj72PbRy2XWanDm0nu83fsyq
         lZaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=8BmtHuypiMEfqlU0Jcg9WpdG/Qk5H7W5BriyJMpqRR0=;
        b=iLrsCpD7wqKaA7VXgsPTyjMm58oSo08wunx8pcABvo3iLEgB44mXAMJr8Xv1PWDj86
         s/mDPcw4zmvejBW6nOqdRSiFRPFTs7yxe7qgD6xhjtggvj2HdXjsUazzE9euI3DCVv1I
         lQovNiAB2UI2GyU7AcaSa0/S+SzmWWiDJXmmCyrNI+JXpJXd8/KBaAg2Ji54mNGEFHgJ
         GRMAVHYAh/nuCnDjHN2QX5HfqAk13vc2VBGQsbdK4sB+/JnxkvPOY4E8Tl2rgzT+pFW+
         D0Uv2+eaaj0ApAL2uA8+vNXjdk+sVfBCEBIWne6PrgZxab8DXQhIt2n0tv+wexEiYfih
         DM0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=FK8LQs2j;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=8BmtHuypiMEfqlU0Jcg9WpdG/Qk5H7W5BriyJMpqRR0=;
        b=ZEGnJJuezhOO8SgZx7o2UK3FHOcbyxFYrsXO14vPlPpiHqWdYHSm+zLzd49s+bCg8C
         BnScnS3cP5jAQF26Ds5LO553lCnpJNqZv6UYO2SGsyNPbs4vRzeiuRFvcmolt7B2zizR
         ZBmyU33GRHbrmtIsBrvnvz8TQeFU12nb7fPZrjLAG1RfuWroZNBk5ufIpQV6gL3zrm5g
         xYkOtE5Bli4LFMYwt5oayYOZS4OKyZXETw8+MNK4jK0qlpCr7WZxVRqm5KSHMfxhQiO9
         Y0Auwo1aId0/CaFASpyVrVi9WHiSEFGK6CScxUAxrJwiReMC8xuDGz/rExjMRQR57hU6
         x1Ew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8BmtHuypiMEfqlU0Jcg9WpdG/Qk5H7W5BriyJMpqRR0=;
        b=zgD/IBcSWeg0r2Y5yZqosoE170qUI8aacDH1aq2R3DmCG6K5779Pl9x3jgmLhubpcO
         0+mNqgw5Zt9dzvLuWEn2N45c3uV8dLGoK75bwoBfooqwdS+LYEnOrkwnznmcvtH8hAdz
         BYCB9Zfl9YABftxAV6ZjAHjyUAmdY9TARt6/VmqGBT9B40Tt1fK++eDw8Z3C4XhseVAH
         xGxYLiXFCI/LBxnoSQ/rTyXXHF11hY2Wdo1zQpETLwCHlyhO75EiFik+nDXF6jY0gJAf
         veGLyvWFnkOYBhWlP2hzJecaLF8UYN/efe8dbYOPFq9evsPaWKTHn1/Gydf4Q6DcawbX
         77UA==
X-Gm-Message-State: AOAM533GqcLcYdVjVYYRE3KGLjaXq6po8xlmaPA+nfmJZ8L7bBYQD167
	dLbCzfu+aOHVa3fw0nrhZnk=
X-Google-Smtp-Source: ABdhPJzxA3fiZUn8S7KUKSbrolWWt9S98g+JqGodY+k/PtpUZqRhNA4FXpLefrSo6VsPygUvewTHuA==
X-Received: by 2002:a1c:9dd4:: with SMTP id g203mr1334061wme.114.1639511767288;
        Tue, 14 Dec 2021 11:56:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:770f:: with SMTP id t15ls1672363wmi.3.gmail; Tue, 14 Dec
 2021 11:56:06 -0800 (PST)
X-Received: by 2002:a5d:4989:: with SMTP id r9mr1271123wrq.14.1639511766208;
        Tue, 14 Dec 2021 11:56:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639511766; cv=none;
        d=google.com; s=arc-20160816;
        b=k2ylOyTb4+3ic4cw8hZbDwlQN62GCJsLRVhw1rzZnDUbgeCzMMMOYmDBakIWIi7ciQ
         oiObyn2QQc6hBIkyU9UxdFkjfvfrNiJdEwKpYAsfmlSQoHBalVBV5Xn9FOLz5GnPAAJz
         IhiKURcmUQyqQhZwbBMjU6Ret1+7dExJ19UL1/p3Qo4x69SjPlwu2O3xgQIxuLFp21US
         i9NCGuFx6KSXNMjDOJwaz9jebsZtUCjiq0d4kPCCLx7Nr6SJu7BXqke3nouMFb4IIRnR
         Ha4wB9qWMBwpzU3yVjGSQAl8LLSzBlsXOnnqMyTjXaqTN262SyymDvO2gwhM5Xtv7EkV
         SLCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=wS77TqqTPnBTpmksYhdz3eSRMai6KqIllrvJewhLyWE=;
        b=vUdCjKj6EmUrIkX19nbBSgERQz0qsSV2FmnjlDfsUxLpJHs394GhGCm4NqPgGDs0N+
         kNw2tyFVY6MSQEFvMzGwuuMqw1ndskmRLIj2UfVL4LOpTkmtYit7YuTDY3A79D/ZHwLL
         qdeM0+9RweE5cV459lApULobUjf41AY3dvbTJf1HqVjhkWL6jAIyj61s6avG+2GxTaFB
         i9FgHvdWJ4SwjfRGWQl/V1zyoCdVshfZGyTYBTmbeJC1bNAMakF0vEkreaUU3xzFB2+Q
         ubXerJq/qEE54VSiz/H3gHU3olYT9AbZSKo2he9bfunhlxCuWrLgZLydnKjYwVJW1Sl6
         Bn3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=FK8LQs2j;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x430.google.com (mail-wr1-x430.google.com. [2a00:1450:4864:20::430])
        by gmr-mx.google.com with ESMTPS id i12si29274wml.2.2021.12.14.11.56.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Dec 2021 11:56:06 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as permitted sender) client-ip=2a00:1450:4864:20::430;
Received: by mail-wr1-x430.google.com with SMTP id u17so34347011wrt.3
        for <kasan-dev@googlegroups.com>; Tue, 14 Dec 2021 11:56:06 -0800 (PST)
X-Received: by 2002:adf:c10e:: with SMTP id r14mr1212852wre.558.1639511765820;
        Tue, 14 Dec 2021 11:56:05 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f9c2:fca2:6c2e:7e9f])
        by smtp.gmail.com with ESMTPSA id bg34sm3343256wmb.47.2021.12.14.11.56.04
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 14 Dec 2021 11:56:05 -0800 (PST)
Date: Tue, 14 Dec 2021 20:55:58 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH mm v3 29/38] kasan, vmalloc: add vmalloc tagging for
 HW_TAGS
Message-ID: <Ybj2zms+c6J3J/pf@elver.google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
 <af3819749624603ed5cb0cbd869d5e4b3ed116b3.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <af3819749624603ed5cb0cbd869d5e4b3ed116b3.1639432170.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=FK8LQs2j;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, Dec 13, 2021 at 10:54PM +0100, andrey.konovalov@linux.dev wrote:
[...]
>  
> +	/*
> +	 * Skip page_alloc poisoning and zeroing for pages backing VM_ALLOC
> +	 * mappings. Only effective in HW_TAGS mode.
> +	 */
> +	gfp &= __GFP_SKIP_KASAN_UNPOISON & __GFP_SKIP_ZERO;

This will turn gfp == 0 always. Should it have been

	gfp |= __GFP_SKIP_KASAN_UNPOISON | __GFP_SKIP_ZERO

Also, not sure it matters, but on non-KASAN builds, this will now always
generate an extra instruction. You could conditionally define GFP_SKIP*
only in the KASAN modes that need them, otherwise they become 0, so the
compiler optimizes this out. (Although I think it does does complicate
GFP_SHIFT a little?)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Ybj2zms%2Bc6J3J/pf%40elver.google.com.
