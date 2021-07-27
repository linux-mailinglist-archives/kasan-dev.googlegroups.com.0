Return-Path: <kasan-dev+bncBDDL3KWR4EBRB4NZQGEAMGQEKRGQ35Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B3813D7E75
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Jul 2021 21:22:26 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id f3-20020a25cf030000b029055a2303fc2dsf19860929ybg.11
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Jul 2021 12:22:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627413745; cv=pass;
        d=google.com; s=arc-20160816;
        b=Eq3O3VuO2794jH66KaIej7F3AFuEBfv7R7MsYxVCPDO21E7ug5T/rlLBiyzg5snqaa
         AUcAeKjvKJJWMnbZ/XZ0OUs3A2pTtL97VzVhmfYPNKq84qgirzMrj5AvKozXX/P+0ShP
         4ubb/ULRl1JmYQN/ZDnlnhTTKfEfNJts4qItpM87gkAOo+TPp6FMd/mYpQ6g7F5j0yN2
         GKjUIvhIzG5M5OE2++2prDoRFhcsVwwiLWMqaEF1v9W/drvJPLPX+Bj64bVdeBSzEVrW
         3XyoF0XIPR81O+cUtyBMMG+22l84IopFEujBMWRIf+wfpG63vilL7YlAY8/dwCLhRX5J
         XykA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=hswq0/DnQijC32I4tJBv8FWjsHG3aZqiACnHYGuN/V8=;
        b=adceDwbipgcTZ9QKK3z4m/oZYKP4ucv/+YYil+Hy7xZKSpsaBYcVOttL8NJjpL39rE
         QH0tqoCXrtdB1im0R15Dm++VhTcjkH+tqRkzkzKybPY0LSHY6+T8UFW0bSkFXWZlPP7n
         TYcPGyLfTUp0PXtBp8WrvmLH4kUP2Waj9lNF75hkj28sqwmzk7rufw4BatAgsA85hZkO
         Zunj4CTP0Uvo0YhmYLXgtq8B/3DO0XusJ2JPVF+hL3T8LBKeSz2hqnUFIuxk72MlrP1o
         csxfeSzzaDe0vsPqW8EAMoHffB5cvQ9pxEuU6ZE3uEvog32Q8Zhzt+15reKA94WuS+7a
         ON7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hswq0/DnQijC32I4tJBv8FWjsHG3aZqiACnHYGuN/V8=;
        b=V9vXNZyvkLjaESzqCGK5UkuVaY7360LFCgJd/FU/A6C7Y9iUIJaLkVtwH17A97IuIr
         Re0qKbXCnBqfJOxtfpHpgItnnrPXK+Ns0Ap1oWEehG2G+ECOpAWha4FtCd+s5wRNA73Z
         g9keuN5VmlQNn1sHaVGIK8vq6IzbUoYUURfelnk89q5imVJrXPI0D6kajhZQMwPgliey
         3E2bHmfwKwsgafPEr1ju3Y6oJIKJHBUa1JKrT/uOWCCHvhX94xvL6KID00syM63MRnrG
         nWfqytn5JKOSN/4TqK+U9yNb1l2cqi782yKEQAV4OknclFJRBuvvvSx1tTC1wO2e5/cw
         iJlg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=hswq0/DnQijC32I4tJBv8FWjsHG3aZqiACnHYGuN/V8=;
        b=JxV8Xi/BmREX7DxZB1mdZy8g/wNqivi7jHEynqhP5LqAdEw3uZMaV7arlvVYQ2ieNt
         wAauc178sEYTrnnrnpUoWkKNwkJ++QHuSSXrNdj/0Q8fJkUIx/o9FVKCgGhxlpLotwnY
         IPlaE9TXw/mvHjBF0T1X4J7aDq/NqJmJBB/EDgDofOsC4VTHpxMt4sW5zvFlPSbMxNpI
         YyiDthiZB4VS4RfpInxFWtjjquGeWWox8RGX6amIu4x7v0kFyodXkxZjuvgLiC8/Y+Qn
         r9utyuc5PrbUj/YfQB0GKWbfvM5cYSxfngOms2is+eIPrWziOZfd0gIqMpKqEdA89F/I
         PLAw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Q3sXxviwOHXcspn5h/KxtUwStY4R7anhx23GOI0taGPGBstZK
	P63/OXm/y4lbB6vv2rybWbk=
X-Google-Smtp-Source: ABdhPJz3HcmLPZNR9Q6XBnjDt2Vkpb7DwcGwdGqxdsRZ9K8a9Q+qK+xk8bo36WfjlteiP5rp/c77QQ==
X-Received: by 2002:a05:6902:4ee:: with SMTP id w14mr29569339ybs.194.1627413745181;
        Tue, 27 Jul 2021 12:22:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:420f:: with SMTP id p15ls2431395yba.6.gmail; Tue, 27 Jul
 2021 12:22:24 -0700 (PDT)
X-Received: by 2002:a25:a4a5:: with SMTP id g34mr31621557ybi.473.1627413744752;
        Tue, 27 Jul 2021 12:22:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627413744; cv=none;
        d=google.com; s=arc-20160816;
        b=M43walvOfewXQSXHjF2D/y2tyoD8mkaugShDRhKq8A9lKRp7AU6bOjjyJid/w9qXXq
         doniWHSeO3AJ1W2/ZaaS31yyNk4nMO0y/ELL6QQLytQn0t6dm8DqbKBtdhVlwU2CRol7
         WLJ/ZfkcPyAnmGJXbgHGhDYqf7aIGDrpnhjwKMWXa+FV/JjCXfo592FyfuJfCM3e64ZX
         iO0AitDuw3cS+nyStHcU22nkg4X8sRA+dSLEsX1DizLzCUEwD4ZPS8sBe5z3IOXOwGvs
         O9XGtyIlweUDXWOZr8a+nI0UZbrVAKYI7Plwo29RK6RvPE0/+My8eJmXUbCBOlUwEJ/b
         ch2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=Qfr/Ueg7NHSh4CuTTl26GluZ/zS5hmB53ASIMGCTviE=;
        b=i8Es3aBoO1DYI/EAdld2DK//cLNcxps06C7U25X/9kU3YIU+MAixsuxdKU3RgjqwqQ
         abR86Z+fnTwvHcH972adrZHztEqX+rXzdjEJ/kbqQThdNDBimd8X+5SEJ9nICTZbe/ah
         wlyMYeXOj5KEMZxGycenlU0WlTJiVJRa8uf/vZcGg0kmt6znf/tOGw28ppxGJALtb62J
         ddoSN7HgxIAQS8KxKrt/pC0EXPvpctyv11ucxHXO5mfFwZKdsHsCEIZ2FPdL0DuYbOhu
         nMDvb1m2IMxo0LKa6GYPAGnnEREZJ7VLMgD44Xwbb+CRLFGGbWavJ13uDpnDvMlmGCt4
         Iq6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id z205si210712ybb.0.2021.07.27.12.22.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 27 Jul 2021 12:22:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 9A76E60F6E;
	Tue, 27 Jul 2021 19:22:21 +0000 (UTC)
Date: Tue, 27 Jul 2021 20:22:18 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: Marco Elver <elver@google.com>,
	Nicholas Tang <nicholas.tang@mediatek.com>,
	Andrew Yang <andrew.yang@mediatek.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Chinwen Chang <chinwen.chang@mediatek.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	linux-mediatek@lists.infradead.org
Subject: Re: [PATCH 1/2] kasan, mm: reset tag when access metadata
Message-ID: <20210727192217.GV13920@arm.com>
References: <20210727040021.21371-1-Kuan-Ying.Lee@mediatek.com>
 <20210727040021.21371-2-Kuan-Ying.Lee@mediatek.com>
 <CANpmjNM03Pag9OvBBVnWnSBePRxsT+BvZtBwrh_61Qzmvp+dvA@mail.gmail.com>
 <b6b96caf30e62996fa3b75ae8d146c9cc0dcbbf6.camel@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <b6b96caf30e62996fa3b75ae8d146c9cc0dcbbf6.camel@mediatek.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Tue, Jul 27, 2021 at 04:32:02PM +0800, Kuan-Ying Lee wrote:
> On Tue, 2021-07-27 at 09:10 +0200, Marco Elver wrote:
> > +Cc Catalin
> > 
> > On Tue, 27 Jul 2021 at 06:00, Kuan-Ying Lee <
> > Kuan-Ying.Lee@mediatek.com> wrote:
> > > 
> > > Hardware tag-based KASAN doesn't use compiler instrumentation, we
> > > can not use kasan_disable_current() to ignore tag check.
> > > 
> > > Thus, we need to reset tags when accessing metadata.
> > > 
> > > Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> > 
> > This looks reasonable, but the patch title is not saying this is
> > kmemleak, nor does the description say what the problem is. What
> > problem did you encounter? Was it a false positive?
> 
> kmemleak would scan kernel memory to check memory leak.
> When it scans on the invalid slab and dereference, the issue
> will occur like below.
> 
> So I think we should reset the tag before scanning.
> 
> # echo scan > /sys/kernel/debug/kmemleak
> [  151.905804]
> ==================================================================
> [  151.907120] BUG: KASAN: out-of-bounds in scan_block+0x58/0x170
> [  151.908773] Read at addr f7ff0000c0074eb0 by task kmemleak/138
> [  151.909656] Pointer tag: [f7], memory tag: [fe]

It would be interesting to find out why the tag doesn't match. Kmemleak
should in principle only scan valid objects that have been allocated and
the pointer can be safely dereferenced. 0xfe is KASAN_TAG_INVALID, so it
either goes past the size of the object (into the red zone) or it still
accesses the object after it was marked as freed but before being
released from kmemleak.

With slab, looking at __cache_free(), it calls kasan_slab_free() before
___cache_free() -> kmemleak_free_recursive(), so the second scenario is
possible. With slub, however, slab_free_hook() first releases the object
from kmemleak before poisoning it. Based on the stack dump, you are
using slub, so it may be that kmemleak goes into the object red zones.

I'd like this clarified before blindly resetting the tag.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210727192217.GV13920%40arm.com.
