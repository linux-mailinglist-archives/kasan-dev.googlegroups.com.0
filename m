Return-Path: <kasan-dev+bncBCCMH5WKTMGRBR6DQ2AAMGQESVOUPNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id B40FD2F7DB4
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 15:08:08 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id e3sf1266430pls.7
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 06:08:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610719687; cv=pass;
        d=google.com; s=arc-20160816;
        b=lemGBsRqRzfdPcTFXWM9kBrQAiT9gM88a/znWXWLfzQ7X0QocJR8PmhByIZNvMqRaX
         6vzXdu9OctzlQSufbWfW6BuLi41CoYtAbQ4swtf8ySMdA+L5KkMSxKmwle/2AO/4jiNl
         tfvn8Tyo899emH8HHTD3maac1XNXfvg7F39FHuApGyU3Nl2z+2LYZW5lw7U1xpAyzQ29
         gmQr0rJ9VOdpJcnrWo53C/4HZwAGpvQ2PdgDXm+FBt1EqFf/ZSjLKNuv2TO8hv8J658d
         d0YjLk6D+j3GGTNq/zBoeBJa71ianTkdT/Lhf8YQpaz+/PcocdGRHKPnVwgYRTP59WqQ
         woDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=9+k4V7gWqgPaSA6GrTBKEijTlzDqMdjKHQZWPCW13f8=;
        b=JSIroBZvxBU5anE0AM021EusGiHfZ04HvgSvebVgFCIfgu9wOL2vUwsg9EZ5A+FCJn
         QBOa2GKgUjW4OAwTw+4ISp/pfFoVhuYaR/NZ6zGQlulsueHtL+Yxn97dYy7BSpufyHh/
         kLr1K/Oux/g1YBHgKLzfoAhNVg+IezQfiQU3ugqfadUqyxBXBr1Rr1o8A0gkypaFi3Ac
         jsdkgYFFGKdj167KsrZhiWOWppYICFvRDYY952CjvJxGXUrVRido5b5XrhlWIc/UJrQn
         o265mCd0vSIceRJu3fVEM5Vztg1Yj/yg+R0J7fU7uim94CFq1ckTlAIXs6hLz/691aHo
         LBHQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AyEz5HFb;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9+k4V7gWqgPaSA6GrTBKEijTlzDqMdjKHQZWPCW13f8=;
        b=bWQlNO1lywIqTzcaUC6paAUSYWkpcO+C/vr7uN6eFQ0EbdHUBI8elQKGOCFzmu6rk8
         /INA8dHgofb8aWZtfMp3O3pA6Gz31CS600AUahjPojG87Ij513yFst9z0mDjcNXVO9Tq
         X34AuDBIA6B4uP1yy1PYXV9Oc5Pfv9OOwvKd3VZM8t6zMiKTDrXXTJwTlV1NkhchLoTh
         PN8ngsuVt5sv/SNthMhWr+pIBTktCXF20xHR8fKLgPhHwY9NbdHn8M0LDr2wpfT25ijA
         zUJq03utg7cJrUtZI7l68VCc8uHA2tw8eu0axQ60wHkW18bBEfTRu2H4dPIfigJFnFRt
         p4wQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9+k4V7gWqgPaSA6GrTBKEijTlzDqMdjKHQZWPCW13f8=;
        b=Cs/j1Glp9W3bc9SS7FrWrBC2qcYhg9fTSWlL4nr/jplj4ApEhRNprqN5Aavaq8v2it
         2Tqv9yZr8MC+k6Gvpn8hlTLQYsS1L+sKKhKrwV8bnf/8jyVyjxn4XNZYlCd+Ld++ZSRS
         QZOaLO9ncIHNFJ7s+YmvgG3m5MHHSavVv68EIlQJwZC5vrl/EWobO2mHpIRUH+BpWs0n
         UBLmlfnABkKvjXL9ny2z5wgU9RS9p0jrkJTun/ZzyjdNcJbudXHHl0UiYuJil6fIBnZX
         CH6R3yFaWVXpXJnF3U5+9vfEtDhuG/h+h/6vUwEyE4Vxz91RSAgi7hqcFFttzjq4x9fY
         QJnw==
X-Gm-Message-State: AOAM530lTU7jQlqzEsDxThY71Z98fuywOnSQB2pSS647kmsa59WergbZ
	ycwgq7Q2TtT5189rksGqKqs=
X-Google-Smtp-Source: ABdhPJxLRn4bPRy3BeQBBYDw0hy+EQiaSGStTCtESmHZRC4IQgw3F+FD1gybbFSC/OyWmJxo1MFQKw==
X-Received: by 2002:a17:902:7248:b029:de:74ae:774f with SMTP id c8-20020a1709027248b02900de74ae774fmr2585041pll.42.1610719687358;
        Fri, 15 Jan 2021 06:08:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d713:: with SMTP id w19ls4474067ply.1.gmail; Fri, 15
 Jan 2021 06:08:06 -0800 (PST)
X-Received: by 2002:a17:902:e808:b029:de:5a8d:c654 with SMTP id u8-20020a170902e808b02900de5a8dc654mr8123179plg.80.1610719686704;
        Fri, 15 Jan 2021 06:08:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610719686; cv=none;
        d=google.com; s=arc-20160816;
        b=thtJ8oW6Uff/w+Bl2L6RfZ05LERFTxlKdZmV41r7nVQZbA3yCmN/Zwz7HPyWU8STtW
         ApJL/te8Aksb2jjfOqOGkOU2Uw+O8vEn3SLhJ9H6dcdvCKX9bkb6cGeuuNzAPdDtpLn0
         5auv5ZMCx0H4GzuYlmNY1J/c65GsXuu83XNyhiQni3SfYcnfSHsMTdXOFMf/hsHaZDcP
         q5ttiZ2t9iu4mKHqMtY6qZ6ibUD3QKr7lbhI1BQ+tQSIPZqCDRXmLM32IxTbEGffu6qT
         zoP6bo8bheTZ9TIXpHc7R5+YbKjRostTjhihKiIM0yCNFqtsfxIpD3Ud7ch7bSk33WRG
         7yVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=S97i6AT8RiIBnpA9TrOdE+WMINZPh3gMrVKaHT8SvQI=;
        b=sBIHMcp4cNCrsrcW3wUGrV9Mnu9qEpVBHjwzgrWVIfR5fpX14/zvYcDmsTi/0Izwy1
         bN2dRpw61Dj+0dEqRlk1iEjKLmU9H/nlqdhcm4yGa5+oKVAW9Ar5az3Mf7oL0GF6C0hV
         2ej37/CUAOvJiuYNSFbW+l4RvIg5nDl9ODywDGUG9TbHGntK4BrfonwkRwFTnjGpiM+g
         I+3vdIEuzFDXTJOW8ARA7kbLyyi2fErTRd6DHbmy5DI2poNE6hx9iprK5VBbu3ipDqvU
         n+VVBkuQ1G2h/zntGy91/L5w5x3IikPAN2UfDCEmhMVSx40hXGpRXy4xYZmFrZU5yPtC
         QN8w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AyEz5HFb;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72e.google.com (mail-qk1-x72e.google.com. [2607:f8b0:4864:20::72e])
        by gmr-mx.google.com with ESMTPS id z9si738744pgv.2.2021.01.15.06.08.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 06:08:06 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72e as permitted sender) client-ip=2607:f8b0:4864:20::72e;
Received: by mail-qk1-x72e.google.com with SMTP id 22so11694262qkf.9
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 06:08:06 -0800 (PST)
X-Received: by 2002:a05:620a:2051:: with SMTP id d17mr12340951qka.403.1610719686159;
 Fri, 15 Jan 2021 06:08:06 -0800 (PST)
MIME-Version: 1.0
References: <cover.1610652890.git.andreyknvl@google.com> <03fae8b66a7f4b85abadc80a2d216ac4db815444.1610652890.git.andreyknvl@google.com>
 <YAGWavYGrpZXVF4M@elver.google.com>
In-Reply-To: <YAGWavYGrpZXVF4M@elver.google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 15 Jan 2021 15:07:54 +0100
Message-ID: <CAG_fn=WSkyBnb5vo5AVpeqodgM=0GSwCrZNePF87SYB1y5fU-A@mail.gmail.com>
Subject: Re: [PATCH v3 11/15] kasan: move _RET_IP_ to inline wrappers
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=AyEz5HFb;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72e as
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

On Fri, Jan 15, 2021 at 2:19 PM Marco Elver <elver@google.com> wrote:
>
> On Thu, Jan 14, 2021 at 08:36PM +0100, Andrey Konovalov wrote:
> > Generic mm functions that call KASAN annotations that might report a bug
> > pass _RET_IP_ to them as an argument. This allows KASAN to include the
> > name of the function that called the mm function in its report's header.
> >
> > Now that KASAN has inline wrappers for all of its annotations, move
> > _RET_IP_ to those wrappers to simplify annotation call sites.
> >
> > Link: https://linux-review.googlesource.com/id/I8fb3c06d49671305ee184175a39591bc26647a67
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> Much nicer!
>
> Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DWSkyBnb5vo5AVpeqodgM%3D0GSwCrZNePF87SYB1y5fU-A%40mail.gmail.com.
