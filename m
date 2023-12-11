Return-Path: <kasan-dev+bncBAABBY7V3SVQMGQEWHZXXQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id A251280D206
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 17:37:56 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id ffacd0b85a97d-3333aaf02b0sf4370351f8f.1
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 08:37:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702312676; cv=pass;
        d=google.com; s=arc-20160816;
        b=VTIuC6Br3DSXUvjTestlq3hfOChWnPSWXnRMaT9P4zY4WiOmdw0+iBCKPbngbKN0iT
         /SgOw4hF5cnoE1jj5OxKWbL2/sUKL/bKtLn6WbzDBbSRIGBE86u7uQWOwne79hkiXtHT
         iUV/XtyO3JH/KAv1X9eI72IcadlKimXrUNWhSk+F4CvlW8hm8GTxUJvo1MguDpssXl1B
         AeoZlT9R5S1rtFSJ6HohdMLiyxdyi+R5ZbsxJltnKAGT9nm1zAo0530wPb5aRZRiusJx
         L9eGz1InV4qPbDg/bh/lqh9LnrolZbX+SeIBbxPuDjTRGRu4V8CFbssx9J9gv57PGQP6
         yTsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=pNIhySTtaYRNn0lAl9zWFDZ1/8zZOHvD2IaibsB27Yc=;
        fh=gHaoT4XMlFH9UYc+/4XPK2hvhU7RMe3yZ8NuTuxuoyo=;
        b=mUn28gWgg3c6iwzB2M4nx07V7A2Anfr9JgpcZ349BBo0Jv+GdvX5m/HY1iOG/X/lzw
         veODfQVZpYGAav/OCsbu74zhMQSbN2mq5K9h9CAzcFcLRsqKSkPSFMHClho/tXoA4Zxe
         IsRv1mc5e0wwqTP7NYWbJssTODCMzXl3ZnUVYjSAuAkZehUXQaLmocxxnvmuupNiLVp9
         zvJ/y88X3tDCkzokFACvFXUSeJarg8z5SV7ugHAwB1yNbBF0Hw2cTgDQ3I118WQWkLcs
         86aAPBT3gdzlBK6Y7XfAMPjkqj119+GrPoXGklSchZkb+nnqkkCu2+7AveKDvR7r+w9I
         CV1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@tum.de header.s=tu-postout21 header.b=mlVfJUG6;
       spf=pass (google.com: domain of paul.heidekrueger@tum.de designates 2001:4ca0:0:103::81bb:ff8a as permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tum.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702312676; x=1702917476; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pNIhySTtaYRNn0lAl9zWFDZ1/8zZOHvD2IaibsB27Yc=;
        b=S90yYpnLuj/KMh7FjoZJzA1Pk1pdDbK2pV3m3ECXj6WsZ8fs2HVJLL3nxznn+X41LQ
         SV0v9GKCWr3hxtYOzUJfKXPkjp1FZPILcEkISHLaAck2SXwiV8bBLlQscDct6oQL8kO8
         k1YaXVXzhWS+HY8opwhs5X7gPo7T6mp2FcI0Qs+IyqETwwBbyR1ffgUWTlbBUkahAGdO
         lXgLJKPsxBYln+j7+r/F7o+BC4W6kkIPpFWIjA9Ef0ICVvHPLQP97ZRjwvwB90kydX6q
         oKqIyl9Xa9B7NnDldsarQd7ZvL1p3WNiGOSl0vhbXbIC7sH4FuAKmAQcvNdWTSeqVvlY
         46lg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702312676; x=1702917476;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pNIhySTtaYRNn0lAl9zWFDZ1/8zZOHvD2IaibsB27Yc=;
        b=WgieZoqZklizj0bhP+vCWEOpgY7obplIuQRwxqFFY7F+xjLqD0NqbsrNCr6engzIjf
         mbfm5Io5i3N5y7bwVHb3cQpxpnOXVlzcfyDfddRqHhzrX11pYW8MPHDHnXKzZ4maOZPs
         PkJzPYXkSnDh1QWRvAPVKAh1/W/SAM5l4Hhi1fBaZH9qY23mZzYlvUpFV2Lu9kPObSFy
         gIKNZs6mkAhvbThyddU69wKyzTU3HXQwBncxhGE6zQVz+0IcR2rfy4zF44Z1+Qlw5mdt
         Ya+Q2zIHpLQZzL0cz4hWib/KwiajYNY52P7bb3y647rNFOIAb/IADxbaNC+7gKJOgfLT
         Odlw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzrSZhjugAHTPiKadjVvcSN0eatRxkXIz7hWfzDiO/PVHDKJFNV
	Ika45ODCo2EB7nLIaB6ygQI=
X-Google-Smtp-Source: AGHT+IHpzi/QytpX3JfrmL/scgTBeoF4MkPwDKFpfHAu1DEoHqNFNT4GZJ7coiSI2dGAG8d1fzegeg==
X-Received: by 2002:a05:6000:136d:b0:333:145a:759b with SMTP id q13-20020a056000136d00b00333145a759bmr2624881wrz.20.1702312675673;
        Mon, 11 Dec 2023 08:37:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fc91:0:b0:333:33e9:256d with SMTP id g17-20020adffc91000000b0033333e9256dls35530wrr.1.-pod-prod-01-eu;
 Mon, 11 Dec 2023 08:37:54 -0800 (PST)
X-Received: by 2002:a05:600c:2191:b0:40c:3177:35d2 with SMTP id e17-20020a05600c219100b0040c317735d2mr2027747wme.233.1702312674159;
        Mon, 11 Dec 2023 08:37:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702312674; cv=none;
        d=google.com; s=arc-20160816;
        b=p08if2bJtBV1vAvyY9QY5WjUOCI3efPIq7MnDokTMcMvMvy7TtIWVnFKAwgYqa25Ci
         gFBzn9yAJuZSji9jOqcN3SX5ZJJD02PGE21Udn9CAX/HCEDi6r8SoO68j61YLx5H83QC
         sT2CUgQjRitD5nG4VV0kAdLvuWAads0/WfgqPxmFrRe/Gr9wBPPozetP7BDSn7HNx2Jk
         heUYCCZFmPaypMGpdJ+dfMjbhtxksLr0Ha9/A5q0Ck9fZVoqbqnkMxvrDQWhdX7N+Mje
         X2pVxFpiyZWRDS2NwqDSunCMckIm2tw/4L6PwN4ZYa8CkP+OmOU5QsHCfyHg1P2cRQHw
         xy8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=i7+HUN9YymZ4vhBFtbMavTxW/F7DkeQt7GVW2zJaY3Y=;
        fh=gHaoT4XMlFH9UYc+/4XPK2hvhU7RMe3yZ8NuTuxuoyo=;
        b=YJZgGfgbLHLO9sU+akHQnYiw/yDCwy/j6al+jC8j2qF+i/Sasz1rwmfw+RXDXsX2zK
         OjTk8xLROnh1n6XkQDA4qSIPxp7eG7v+VQi09HQJxJ1TOTOtlKZGlJqS4fCi4yn1YEkm
         qgmzgG+k1EYFX3St3JidNC+ZsGWc5TyCeS2o92QDlzQAy/GspLhzWzL7bO+s3hDMQwEF
         44mAxCsZ+B5K/5JAzQKjRqLhMtFcy+07BLxf2HKX9Z4sFVxsbiPGz7kN1zv9QR1LUpwP
         VOmzMhvRIumWlvczVouIk3SNIuvZHFzrtyj2sK6OgzbOxBaTEP4DwrehpIcKY+pbpYez
         zIsQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@tum.de header.s=tu-postout21 header.b=mlVfJUG6;
       spf=pass (google.com: domain of paul.heidekrueger@tum.de designates 2001:4ca0:0:103::81bb:ff8a as permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tum.de
Received: from postout2.mail.lrz.de (postout2.mail.lrz.de. [2001:4ca0:0:103::81bb:ff8a])
        by gmr-mx.google.com with ESMTPS id s21-20020a7bc395000000b0040b4055397csi510245wmj.1.2023.12.11.08.37.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 11 Dec 2023 08:37:54 -0800 (PST)
Received-SPF: pass (google.com: domain of paul.heidekrueger@tum.de designates 2001:4ca0:0:103::81bb:ff8a as permitted sender) client-ip=2001:4ca0:0:103::81bb:ff8a;
Received: from lxmhs52.srv.lrz.de (localhost [127.0.0.1])
	by postout2.mail.lrz.de (Postfix) with ESMTP id 4SpnV85qdXzyVM;
	Mon, 11 Dec 2023 17:37:52 +0100 (CET)
X-Virus-Scanned: by amavisd-new at lrz.de in lxmhs52.srv.lrz.de
X-Spam-Flag: NO
X-Spam-Score: -2.883
X-Spam-Level: 
X-Spam-Status: No, score=-2.883 tagged_above=-999 required=5
	tests=[ALL_TRUSTED=-1, BAYES_00=-1.9, DMARC_ADKIM_RELAXED=0.001,
	DMARC_ASPF_RELAXED=0.001, DMARC_POLICY_NONE=0.001,
	LRZ_DMARC_FAIL=0.001, LRZ_DMARC_FAIL_NONE=0.001,
	LRZ_DMARC_POLICY=0.001, LRZ_DMARC_TUM_FAIL=0.001,
	LRZ_DMARC_TUM_REJECT=3.5, LRZ_DMARC_TUM_REJECT_PO=-3.5,
	LRZ_ENVFROM_FROM_MATCH=0.001, LRZ_ENVFROM_TUM_S=0.001,
	LRZ_FROM_ENVFROM_ALIGNED_STRICT=0.001, LRZ_FROM_HAS_A=0.001,
	LRZ_FROM_HAS_AAAA=0.001, LRZ_FROM_HAS_MDOM=0.001,
	LRZ_FROM_HAS_MX=0.001, LRZ_FROM_HOSTED_DOMAIN=0.001,
	LRZ_FROM_NAME_IN_ADDR=0.001, LRZ_FROM_PHRASE=0.001,
	LRZ_FROM_TUM_S=0.001, LRZ_HAS_CT=0.001, LRZ_HAS_IN_REPLY_TO=0.001,
	LRZ_HAS_MIME_VERSION=0.001, LRZ_HAS_SPF=0.001,
	LRZ_MSGID_LONG_50=0.001, LRZ_MSGID_NO_FQDN=0.001,
	LRZ_NO_UA_HEADER=0.001, LRZ_SUBJ_FW_RE=0.001,
	LRZ_URL_PLAIN_SINGLE=0.001, T_SCC_BODY_TEXT_LINE=-0.01]
	autolearn=no autolearn_force=no
Received: from postout2.mail.lrz.de ([127.0.0.1])
	by lxmhs52.srv.lrz.de (lxmhs52.srv.lrz.de [127.0.0.1]) (amavisd-new, port 20024)
	with LMTP id qxvPLSwCoF-F; Mon, 11 Dec 2023 17:37:51 +0100 (CET)
Received: from Monitor.dos.cit.tum.de (Monitor.dos.cit.tum.de [IPv6:2a09:80c0:38::165])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by postout2.mail.lrz.de (Postfix) with ESMTPSA id 4SpnV65Z38zyTN;
	Mon, 11 Dec 2023 17:37:50 +0100 (CET)
Date: Mon, 11 Dec 2023 17:37:38 +0100
From: Paul =?utf-8?Q?Heidekr=C3=BCger?= <paul.heidekrueger@tum.de>
To: Steven Rostedt <rostedt@goodmis.org>
Cc: Peter Collingbourne <pcc@google.com>, Marco Elver <elver@google.com>, 
	andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>, Masami Hiramatsu <mhiramat@kernel.org>, 
	linux-trace-kernel@vger.kernel.org, Nick Desaulniers <ndesaulniers@google.com>
Subject: Re: [PATCH v3 1/3] kasan: switch kunit tests to console tracepoints
Message-ID: <n37j6cbsogluma25crzruaiq7qcslnjeoroyybsy3vw2cokpcm@mh7r3ocp24cb>
References: <ebf96ea600050f00ed567e80505ae8f242633640.1666113393.git.andreyknvl@google.com>
 <CAMn1gO7Ve4-d6vP4jvASQsTZ2maHsMF6gKHL3RXSuD9N3tAOfQ@mail.gmail.com>
 <CANpmjNNvGL--j-20UxqX_WjeXGiAcjfDAQpfds+Orajz0ZeBsg@mail.gmail.com>
 <CAMn1gO6reT+MTmogLOrOVoNqzLH+fKmQ2JRAGy-tDOTLx-fpyw@mail.gmail.com>
 <CANpmjNN7Gf_aeX+Y6g0UBL-cmTGEF9zgE7hQ1VK8F+0Yeg5Rvg@mail.gmail.com>
 <20230215143306.2d563215@rorschach.local.home>
 <CAMn1gO4_+-0x4ibpcASy4bLeZ+7rsmjx=0AYKGVDUApUbanSrQ@mail.gmail.com>
 <CAMn1gO6heXaovFy6jvpWS8TFLBhTomqNuxJmt_chrd5sYtskvw@mail.gmail.com>
 <20230505095805.759153de@gandalf.local.home>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230505095805.759153de@gandalf.local.home>
X-Original-Sender: paul.heidekrueger@tum.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@tum.de header.s=tu-postout21 header.b=mlVfJUG6;       spf=pass
 (google.com: domain of paul.heidekrueger@tum.de designates
 2001:4ca0:0:103::81bb:ff8a as permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tum.de
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

Hi all!

On 05.05.2023 09:58, Steven Rostedt wrote:
> On Mon, 1 May 2023 15:02:37 -0700
> Peter Collingbourne <pcc@google.com> wrote:
> 
> > > > "ftrace" is really for just the function tracing, but CONFIG_FTRACE
> > > > really should just be for the function tracing infrastructure, and
> > > > perhaps not even include trace events :-/ But at the time it was
> > > > created, it was for all the "tracers" (this was added before trace
> > > > events).  
> > >
> > > It would be great to see this cleaned up. I found this aspect of how
> > > tracing works rather confusing.
> > >
> > > So do you think it makes sense for the KASAN tests to "select TRACING"
> > > for now if the code depends on the trace event infrastructure?  
> > 
> > Any thoughts? It looks like someone else got tripped up by this:
> > https://reviews.llvm.org/D144057
> 
> Yeah, it really does need to get cleaned up, but unfortunately it's not
> going to be a trivial change. We need to make sure it's done in a way that
> an old .config still keeps the same things enabled with the new config
> settings. That takes some trickery in the dependency.
> 
> I'll add this to my todo list, hopefully it doesn't fall into the abyss
> portion of that list :-p
> 
> -- Steve

Just adding to Peter's concern re: CONFIG_KASAN_KUNIT_TEST's dependency on 
CONFIG_TRACEPOINTS.

I'm having no luck running the KASan KUnit tests on arm64 with the following 
.kunitconfig on v6.6.0:

	CONFIG_KUNIT=y
	CONFIG_KUNIT_ALL_TESTS=n
	CONFIG_DEBUG_KERNEL=y
	CONFIG_KASAN=y
	CINFIG_KASAN_GENERIC=y
	CONFIG_KASAN_KUNIT_TEST=y

CONFIG_TRACEPOINTS, which CONFIG_KASAN_TEST relies on since the patch this 
thread is based on, isn't defined for arm64, AFAICT.

If I comment out the dependency on CONFIG_TRACEPOINTS, the tests appear to run, 
but KUnit isn't picking up the KASan output.

If I revert the patch, the above .kunitconfig appears to work fine on arm64 and 
the tests pass.

The above .kunitconfig works as intended on X86, no changes necessary. 

Am I missing something?

Many thanks,
Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/n37j6cbsogluma25crzruaiq7qcslnjeoroyybsy3vw2cokpcm%40mh7r3ocp24cb.
