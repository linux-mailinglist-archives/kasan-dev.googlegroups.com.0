Return-Path: <kasan-dev+bncBDEZDPVRZMARBIPHYCPAMGQEF73WRGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3c.google.com (mail-vk1-xa3c.google.com [IPv6:2607:f8b0:4864:20::a3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 21C6A67A334
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Jan 2023 20:38:11 +0100 (CET)
Received: by mail-vk1-xa3c.google.com with SMTP id u187-20020a1fabc4000000b003ca3e899f8fsf6497472vke.22
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Jan 2023 11:38:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674589090; cv=pass;
        d=google.com; s=arc-20160816;
        b=omh168Fm4yqjTS7kKXiUCjP4VPGrwJiEdRHz3/yNL1hPWkcW4arh1CZgiUGXfzQGK9
         gzzcia9l2/sMziEueT6Sa4z0GSi4Ffg7W92YlSdOvXtyFDhVZzuAh20k4OhKX4HTWrmq
         oIHqo7piTQcldYzq0KoZpBS/O6t/UCNPJjEwdEg71vZlDafxNRfykuXimTIop3koDqHP
         g+wzEe+BoLIb7Kyp58mIpz8uIkQRI0PJY7omdQ38ZhpMpD3PMXmGPtCfqay/W38ef+V0
         4L8NrSIDFzKj26RZ2VyxdyZxbWHhoF7/A5ZqdWNsEnku8J37tqSMNhmfMTKnM8/VEdlI
         N61A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=79A6+vqq/4BQfqzTJWrFKhsw1AfA53GuMkcMyeo1seo=;
        b=mTCmLJLSitebA7C8Yd28Dmv/VIvPvoj58hTvFspUj4nZ4KJUji6x1Gl89iV6WfnmGT
         T5YelcSB06Prs/mLy/YRyIQHRj4Ys8mx/110rnxOvdE/uDFZmA1wzFWKdOnZdusLPsye
         3/vTAZZ5sso3BrIL6THmzaOTZxIs+/RedQn0VtV+YX2g0N2kqCL3fEw9lqpNbirGDshu
         Cuf3s4E20KVuuOJuXfN5gPtdlb7/Dh/K7xUWvF+bdt0oBZhozUV/hqgWwLxffmMJFu/K
         KeMkhpyNJvMlY+VbDuMxPGe9KsIvAErC8yYbESLPhmR1qessrJCbhSs2KCdGnzZq2hXo
         h/pQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mGX2BR1N;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=79A6+vqq/4BQfqzTJWrFKhsw1AfA53GuMkcMyeo1seo=;
        b=S7BmHF00svxigw8Ue6NHaNNPJns1a4puO3quaXhDfeu5CaQIDOLckvtLMTukZ3mU8Y
         7bU5+Zniii8iWg+aR7TFgQYViOERXFzY4ZF0V+41U3ZmJddWk6PZcPojjnKbC+CC7Iuq
         91KO+FcNTGwF79TIBzWd0WCEJwUPxJ3eaLpelvmMaTFDhCOEQiAOcwAz5IAwMMTKKU8W
         sDxbRdAPXQiBsB4iK9r5br9tmZj6G/O5E2FwVqiFYFgcHGlCaizHaRgszLrFJep776fq
         AB/24x5+maFn3vrykRfmrOC8CcGLW8ewMMi9xbHh57rO3Xkk5C7STLx9eXVGeHiY16SC
         M12A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=79A6+vqq/4BQfqzTJWrFKhsw1AfA53GuMkcMyeo1seo=;
        b=sp+P7q00zo2Uk/SlZ+y159Ql+54vW/bnEQzqmDZRWhET0ydi+w+LjLGyB6yjY7Iycz
         W+G1HbZW3MHmu633l4jpneisyWOh9WRrDkBfyizN023aifOxww/jIaGfXw14EJ0I3UGQ
         9T8nDH70HaUo2n5AocRl1G90sZJMc559zqU08dN+y6CNC0u3JPpCyCAk0rYC+OxAw0C3
         awSeP1SK+2ZCPuvQl/nh8Yc8UGI5hQ0Qs6lhVznKvmZHYjt2chc6XdjCNlIz8p2Aetfp
         Oxu3BRZ+95vaQ7T3J34Jc/DVDRQGG4AhWteKQwKFVefyzsOhIzL11v7JWZ17O5JtwlCL
         4/hA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2krUlcpjF8tcCwi2yLzqzSY0M8pJxTi3eea3BLgUd8L7wRUP76bt
	AT0T7yS2kXOh5Uy+8vNxeCA=
X-Google-Smtp-Source: AMrXdXuVqpJb6UAQuppMcecLWUFMDLnmiYR4b9s3y6Odyd6Gkf/3nUl/QpvBAy49wjWMDsiOPmm8UQ==
X-Received: by 2002:a67:fe4f:0:b0:3c6:c5a3:9ad7 with SMTP id m15-20020a67fe4f000000b003c6c5a39ad7mr3911177vsr.46.1674589089972;
        Tue, 24 Jan 2023 11:38:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:20ca:0:b0:3b5:df37:23a6 with SMTP id g193-20020a1f20ca000000b003b5df3723a6ls2894683vkg.7.-pod-prod-gmail;
 Tue, 24 Jan 2023 11:38:09 -0800 (PST)
X-Received: by 2002:a05:6122:e26:b0:3bd:4318:1dcc with SMTP id bk38-20020a0561220e2600b003bd43181dccmr17987598vkb.5.1674589089363;
        Tue, 24 Jan 2023 11:38:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674589089; cv=none;
        d=google.com; s=arc-20160816;
        b=zWSoc6eZTfYbNAvYZWiyRtJJ3FzKNZOncq2uFouzUNSxypZEvbvDeZc89KChRgSMtC
         fv+Q8L99fp+Al0fBadAY1jiO2EJZ1/c0DULeZI0dha0HQBIlJ4UZtMSI6hPKC9f7quDl
         Ww5dJ2v72xf+f7imZwyybOaxmodtc6v44YLWEfLTR2KrngwLV/1f3kPrxZV3Xb2786qd
         eDspqfPemV966HTQ7ZZ836pyjn/jRHTNu0hta1N8sqdz+qgsTyuyThvwh/LJcjvlsuV8
         LAl62vfR0Aa9HOtFBK7eKrBK4AEZ8TKFbKLu6/jIZzNcoEx7O0EwvvYIQsRGHOAnPFPG
         qsQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=HBXM1E6oDfju2EWBGoS3zfXb4H4GcGq2UjIVuFOpppQ=;
        b=csg3s9R4Zce1ByNRK2z1KhxygkmlBgVS5LjxoRdB3UbBo9nhLyUtXVlGpCvzM8OCHW
         MW9HWo5jBtc+1VuT11SJi2aTedaviPOjF8vf+eAKHOsR32HJQpCEGL5JwUrZ9/strN21
         BHS/9FJ65OvCnGP2DklMg/f/pVaBiORIOkgaVrdza+3TL/KGo14HWFmTXx1r0oD/32GF
         hvw1Mo1Y5sUtzcD3ShzYqxgOH3Ia8wH3pc2BLIqgYeTOH5lLWPI5VAZsXWxyyWDjSmv7
         WKg0DJyjCXEcjffFUG7DvBn0BfuTBH8SMdqBsLW//PiKotMHbeEbTsNPxR6w2boyVtHa
         R5VA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mGX2BR1N;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id u19-20020ac5c933000000b003daf0a8001asi230504vkl.2.2023.01.24.11.38.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 24 Jan 2023 11:38:09 -0800 (PST)
Received-SPF: pass (google.com: domain of ebiggers@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id E05D261323;
	Tue, 24 Jan 2023 19:38:08 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 076E3C433EF;
	Tue, 24 Jan 2023 19:38:06 +0000 (UTC)
Date: Tue, 24 Jan 2023 11:38:05 -0800
From: Eric Biggers <ebiggers@kernel.org>
To: Kees Cook <keescook@chromium.org>
Cc: Seth Jenkins <sethjenkins@google.com>, SeongJae Park <sj@kernel.org>,
	Jann Horn <jannh@google.com>, Luis Chamberlain <mcgrof@kernel.org>,
	Greg KH <gregkh@linuxfoundation.org>,
	Linus Torvalds <torvalds@linuxfoundation.org>,
	Andy Lutomirski <luto@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	tangmeng <tangmeng@uniontech.com>,
	"Guilherme G. Piccoli" <gpiccoli@igalia.com>,
	Tiezhu Yang <yangtiezhu@loongson.cn>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	"Eric W. Biederman" <ebiederm@xmission.com>,
	Arnd Bergmann <arnd@arndb.de>, Dmitry Vyukov <dvyukov@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Juri Lelli <juri.lelli@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Ben Segall <bsegall@google.com>,
	Daniel Bristot de Oliveira <bristot@redhat.com>,
	Valentin Schneider <vschneid@redhat.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	David Gow <davidgow@google.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Baolin Wang <baolin.wang@linux.alibaba.com>,
	"Jason A. Donenfeld" <Jason@zx2c4.com>,
	Huang Ying <ying.huang@intel.com>,
	Anton Vorontsov <anton@enomsg.org>,
	Mauro Carvalho Chehab <mchehab+huawei@kernel.org>,
	Laurent Dufour <ldufour@linux.ibm.com>,
	Rob Herring <robh@kernel.org>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-doc@vger.kernel.org, linux-hardening@vger.kernel.org
Subject: Re: [PATCH v3 2/6] exit: Put an upper limit on how often we can oops
Message-ID: <Y9AzndICHRElk4jI@sol.localdomain>
References: <20221117234328.594699-2-keescook@chromium.org>
 <20230119201023.4003-1-sj@kernel.org>
 <CALxfFW76Ey=QNu--Vp59u2wukr6dzvOE25PkOHVw0b13YoCSiA@mail.gmail.com>
 <202301191627.FC1E24ED5@keescook>
 <Y9ApdF5LaUl9dNFm@sol.localdomain>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Y9ApdF5LaUl9dNFm@sol.localdomain>
X-Original-Sender: ebiggers@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=mGX2BR1N;       spf=pass
 (google.com: domain of ebiggers@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=ebiggers@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Tue, Jan 24, 2023 at 10:54:57AM -0800, Eric Biggers wrote:
> On Thu, Jan 19, 2023 at 04:28:42PM -0800, Kees Cook wrote:
> > On Thu, Jan 19, 2023 at 03:19:21PM -0500, Seth Jenkins wrote:
> > > > Do you have a plan to backport this into upstream LTS kernels?
> > > 
> > > As I understand, the answer is "hopefully yes" with the big
> > > presumption that all stakeholders are on board for the change. There
> > > is *definitely* a plan to *submit* backports to the stable trees, but
> > > ofc it will require some approvals.
> > 
> > I've asked for at least v6.1.x (it's a clean cherry-pick). Earlier
> > kernels will need some non-trivial backporting. Is there anyone that
> > would be interested in stepping up to do that?
> > 
> > https://lore.kernel.org/lkml/202301191532.AEEC765@keescook
> > 
> 
> I've sent out a backport to 5.15:
> https://lore.kernel.org/stable/20230124185110.143857-1-ebiggers@kernel.org/T/#t

Also 5.10, which wasn't too hard after doing 5.15:
https://lore.kernel.org/stable/20230124193004.206841-1-ebiggers@kernel.org/T/#t

- Eric

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y9AzndICHRElk4jI%40sol.localdomain.
