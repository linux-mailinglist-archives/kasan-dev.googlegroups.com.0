Return-Path: <kasan-dev+bncBCF5XGNWYQBRBPGAU6PAMGQETFY2VTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 6FF566747FB
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Jan 2023 01:28:46 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id g7-20020a636b07000000b004d1c5988521sf1761218pgc.22
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Jan 2023 16:28:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674174525; cv=pass;
        d=google.com; s=arc-20160816;
        b=f6tiYKcOeSaReMYTEGMjjZYCxxcyVQ0ITGMxVTxzUswAlc6Nni8xEWLMTxub9u5wO0
         LgGJWwEJ1rZB0AwnU9eWCV9U32MY71z835Z8IALEqIIzveu4dsKe1HuWLbRLfs0XsngA
         VxrVz7QpKnrlIOCP1tq275Y23C8IunS6Oj7c+HzXpwOWmvufUPLkwiXe0YKxeF2puVrq
         rPxFA+uPmu7HK1mIkUKeEPKpS2kc5iSvU95eYKISOvzrfXWRytpG73rb9FK9FYwZlwSS
         TogURlWl5RI9mQVV3J7d4bIzDMWHjEOnyRvaTNCxRQLlfBPYsqImxo6VRrFlZU4AKtIa
         B87g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=HqmWfXvxZ2ZvPApYrGIeLfMnaV48G0S9IgATQ7nmB7w=;
        b=R19mep8uML4V71IrnCQVeY5Khkvs1XwFLsfxdIr7O0R+oES4/3Xt5etcJnzdKGjrhE
         8MjGD8tHd4AmFinCA/SMKopjAnJqh8a8rrcyDvprTFGsjSIs3ucc1gMdYN2aI7NYlP9+
         b2WsKY4JyH7UFqJKVofZOaPVQhxMDEuJJm1CoNC/oLqY02r/yAQDfZ94I7DJH+Jk4Sd4
         d0TpMhLU5pfIF0pY57tPJSw8Uq5hcWDuE0Jk1UIKD7eaJQLvzbI3mnyzR6lzluNymyiS
         sLDCOT0nPR365NAcQ/SDJywJw8Pkhwx+mp3uDwbrcLxx4lJt4yfcIMgRjCtnIxzfGpM2
         cw1w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="bo7wkN/I";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::102d as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HqmWfXvxZ2ZvPApYrGIeLfMnaV48G0S9IgATQ7nmB7w=;
        b=W20yg5Sah+rghkp2+H5SOmd6KM8nO+OrQDxAgKR/c2kEUKbDJMaDVmlfQuSuazhHq4
         H+/UMDyddd/XIz8tiWr4gQfDP9hdMJeoijRXRAvgwhUbt3e/v5nf2b0MuIMdlcBc6B+O
         aumRvFRMDjmKrrDB/wsSeQrlaXDK11TGBsoFRy/AySbxrODvjLYahZxcfZ7+eXN59IvX
         yPhSwMNIEBxkZqEiRtxglAl6Tt270nwloPbWygyorJLLfVIyIfxYxHT94232BbpEW0wh
         GeUHjkwfBGHYEVG0WvBvfSc0jR+Z5xU57G8KM8GQDQ8B78ekIfa9KkChMpW9Or9/Qift
         5KYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=HqmWfXvxZ2ZvPApYrGIeLfMnaV48G0S9IgATQ7nmB7w=;
        b=JH1CgbUCm6SB6w/9eg8iRUpVidaN1/wj2Gw7JbFHq8k9NMo9ZaerAxi2zIdZWmQWH/
         ROlOhTiwTQ4G0srWrMKiiEpNtKxMSmv8wKscBMOzcbvKlxEO4pQ5eYvr2yW1/XO1NaF4
         LpgvOcm0P4I+q09Xcpnc/iVwS2A7/WA01/mgEYR4C67mA7tGduMnhXGjnCIptkPo+AOp
         mSgv4LmINuQzLokT9z4vfTvA77U7xAk2KFS1LRW+JwGnlonaDf/xWwfOQxT23nf/fvNK
         a+2DV/cTT0FnJVhZ8wxdlmLMg4L+eR0NJR3JLv54+Mxu49pTpx928h8jG1I6wU+Tm86d
         zfuQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2krlZfogQQRs6k9MW+I6phLP4HD0xWsC0CMcWay5hkgjobsoSP6F
	EfeqUTdkmb9UyV4sdASyir8=
X-Google-Smtp-Source: AMrXdXtxcnexxOHZZo4+RNWOdePmPOm1Mc+ElOygmA8QtLkN0+pINCVSiaoNqAKrOOLX50JOXF2ohQ==
X-Received: by 2002:a63:758:0:b0:4cf:bffc:4029 with SMTP id 85-20020a630758000000b004cfbffc4029mr1052331pgh.42.1674174524814;
        Thu, 19 Jan 2023 16:28:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2649:b0:188:b504:8ce4 with SMTP id
 je9-20020a170903264900b00188b5048ce4ls3477184plb.7.-pod-prod-gmail; Thu, 19
 Jan 2023 16:28:44 -0800 (PST)
X-Received: by 2002:a17:903:2581:b0:194:8ddc:7d0e with SMTP id jb1-20020a170903258100b001948ddc7d0emr11776568plb.65.1674174524082;
        Thu, 19 Jan 2023 16:28:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674174524; cv=none;
        d=google.com; s=arc-20160816;
        b=wfvHHuqCs6dutFbIW2kSpSL8g5S9o73SU/yFVqNjSI8mx6sJ3tk6DepmtgEdbVSr8Z
         hc5ObG+1GzoZWJVojedWQ/b/eSw/zdlrXIXl4KOOFC/IH7h7hddVWdFvXDrGk/5jaUOE
         muU0uMZocXwsBvucd0hGpJ3Sczpbser6vTQHkNVUNDyizPODz7JhS6rS9pOaHrTRx9u2
         LRfR+6QzWve5c1SZA1/KMmma2cl98A0MvX341D+shQqNkLwdQFz7vykNR1/fnGWlMCGL
         JtsXhX2O7cREDVfeKe7nvRznPeyReiMM2vrv4PWAFJ/y2lcdzhEIM7WEkLdEY3aUZpsg
         HgTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=IZAy1Y8poHiv3/DrHCdfFCmw0t4/q9CU42X5LVblr5A=;
        b=usGpEN0MP5mso2yrw0dg53JesyXYethJYNttVFt12qOazAFPqkjeV9RAgneuArDjKL
         QxGhCe66TJa15jWp3eOhvNBlTw33ukFuEsPL9pqQUzTuvRYswr/IS4yLnmpQe9l7R4dk
         sbNC/dDUMhxoxLwsQMTvSSey/nIeNyOpwtcO+CgYG9juyjagAjTf68k1GBzQOtxgajfR
         O2tP9o535Ep1qQI5El+62rSbjxoxdBQ4TVv0qNuJZbnGveMdxEi+VTcXAXXnwSc7Wntr
         iFj3ZSxT5E6RibkFWDSo+nkSIoVsjeQJ+4q/K/t0jcNCB2ygCahMb001ME9YHzPpct2e
         N5iQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="bo7wkN/I";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::102d as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pj1-x102d.google.com (mail-pj1-x102d.google.com. [2607:f8b0:4864:20::102d])
        by gmr-mx.google.com with ESMTPS id u4-20020a17090341c400b00194bda5fdefsi585262ple.12.2023.01.19.16.28.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 19 Jan 2023 16:28:44 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::102d as permitted sender) client-ip=2607:f8b0:4864:20::102d;
Received: by mail-pj1-x102d.google.com with SMTP id n20-20020a17090aab9400b00229ca6a4636so6679265pjq.0
        for <kasan-dev@googlegroups.com>; Thu, 19 Jan 2023 16:28:44 -0800 (PST)
X-Received: by 2002:a17:903:11c7:b0:194:58c7:ab79 with SMTP id q7-20020a17090311c700b0019458c7ab79mr16848873plh.63.1674174523771;
        Thu, 19 Jan 2023 16:28:43 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id k15-20020a170902d58f00b001947c22185bsm11085080plh.184.2023.01.19.16.28.42
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 19 Jan 2023 16:28:42 -0800 (PST)
Date: Thu, 19 Jan 2023 16:28:42 -0800
From: Kees Cook <keescook@chromium.org>
To: Seth Jenkins <sethjenkins@google.com>
Cc: SeongJae Park <sj@kernel.org>, Jann Horn <jannh@google.com>,
	Luis Chamberlain <mcgrof@kernel.org>,
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
	Eric Biggers <ebiggers@google.com>,
	Huang Ying <ying.huang@intel.com>,
	Anton Vorontsov <anton@enomsg.org>,
	Mauro Carvalho Chehab <mchehab+huawei@kernel.org>,
	Laurent Dufour <ldufour@linux.ibm.com>,
	Rob Herring <robh@kernel.org>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-doc@vger.kernel.org, linux-hardening@vger.kernel.org
Subject: Re: [PATCH v3 2/6] exit: Put an upper limit on how often we can oops
Message-ID: <202301191627.FC1E24ED5@keescook>
References: <20221117234328.594699-2-keescook@chromium.org>
 <20230119201023.4003-1-sj@kernel.org>
 <CALxfFW76Ey=QNu--Vp59u2wukr6dzvOE25PkOHVw0b13YoCSiA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CALxfFW76Ey=QNu--Vp59u2wukr6dzvOE25PkOHVw0b13YoCSiA@mail.gmail.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b="bo7wkN/I";       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::102d
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Thu, Jan 19, 2023 at 03:19:21PM -0500, Seth Jenkins wrote:
> > Do you have a plan to backport this into upstream LTS kernels?
> 
> As I understand, the answer is "hopefully yes" with the big
> presumption that all stakeholders are on board for the change. There
> is *definitely* a plan to *submit* backports to the stable trees, but
> ofc it will require some approvals.

I've asked for at least v6.1.x (it's a clean cherry-pick). Earlier
kernels will need some non-trivial backporting. Is there anyone that
would be interested in stepping up to do that?

https://lore.kernel.org/lkml/202301191532.AEEC765@keescook

-Kees

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202301191627.FC1E24ED5%40keescook.
