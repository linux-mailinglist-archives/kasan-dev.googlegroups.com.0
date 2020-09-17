Return-Path: <kasan-dev+bncBCSJ7B6JQALRBPWAR75QKGQEMOKHVZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 57A9B26E80B
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 00:16:32 +0200 (CEST)
Received: by mail-vk1-xa3f.google.com with SMTP id e2sf830269vkn.11
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 15:16:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600380991; cv=pass;
        d=google.com; s=arc-20160816;
        b=YblSriqoQ+G1LZq8DmWl5EJ4ONGEz/Rruy/WSv9LidcXlQUE9Tv/iaY5uZfdc4fUJS
         aZUgIwsCdl7iv2wHZrYsKPe4ZqvU6GrGVqSWc2tGMnaAqmXs7W4/c8J6psXmzIO6Yed8
         1kTLvZFou7yPd/MIsVSPWsMFfXTYeL5NmBawBiqZ9UUpJqHoviGNmVVw0gRV13QjS+VR
         7PRCVfsGUd82UMShQHlO5+ue/YbSRdW1ieNPwwlko/BBsBad083NU725WeAfTuKEgtXk
         gaLWF5PTGGiq0GrCoy5lVthRRgzo7p8mc5MkkmquRe4njmRwMD6kggmrwH5n/ZkVHyue
         iTGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=S38L5hLSED+HKlUopI5IDrhI8dSDjGRO5taw/r7K2LA=;
        b=FoYoTJLDz25JDhsjwJ6PsXmzUSYE2UBzEBpThS/wW/n8GmEX55QoJfPO3xW2JQWQYX
         YycsNhYqfQMcpIjBp7Oq8LDZegQ/UO1/hF3kr3TONgacnxizdI9Nj025U3NG8LeuUTrg
         0itOaWupHj0bDi7ZgMuQH/qbiG2OwoCnxSHLf/kGUxkUkCW17tSyLIwKoK5vysHClFEa
         L9Z+zlBwRhvI5NYudXqvw6HH9edqBS9m//zt9KeAmetZW64CPI3ThN0/jZu2lXbFWDUC
         rGLh4d+np2k0aq48UlKyzL9pEwJW/JJCw/r5Ibq3vxuY3O9Q4oqcflBOjj7FLHydEJq0
         vgcw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Dk3WOStG;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates 63.128.21.124 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=S38L5hLSED+HKlUopI5IDrhI8dSDjGRO5taw/r7K2LA=;
        b=d/+6pQhvC+IvxfqEcweHVFN/gUBk1Mp0inxuWbLo9M2HKqt3QI/R9fz5hkTqQu6RxB
         Nw6BOmJ7+Hk9DuJTRkjyv6yCysVsC0va0y5gqLFVqnrq6LKKOTgreFGEOjBagw9OM24P
         MKqANVFq+rS+ybfqgkOfReVNffEBd4MdKQUw6R9z4cTkfa5BuJSuwDSiw3cqQCDA1x3I
         OYHYLDp4V3VUW5/MOujB1pug7UNDuA0vy2y+Ea2+wc1U3aVYco5Y2fveE1uApagwiLev
         ZR61Eeih72XXOIsf3i9rs2geIc5D17J3hdiI3RSAU4OqTWDJZYvo/bNFc4hmOkGmP5AI
         9MDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=S38L5hLSED+HKlUopI5IDrhI8dSDjGRO5taw/r7K2LA=;
        b=PJoxGxGAE2talfB6ORmWsQUnTQzw9ed7TySQdfHW4LAoxJSQs1YMvbHGENYzCeRAEy
         u39+wjf7lmHlHyNThnHwlQMemBttoRvW6ao+VXnZbw5rBDWNaHGP3GUMNBtqiedIDkF7
         6x07HlOmwSP0EqjEEg8doivwsDMxEZEUz0TXn5/Z3DgNAUS4pfN1croOv6y+9FY7HjZ+
         z6zZOH2Rul5L3/zsurjgjFs6ZFFzVPPVGiZc8H3SwpxBLnQfKLbkM1aygbocya2TQu9Z
         GTJA8oP3EosxJ0Te0dxZYgrvjwV+NJgxcKfvyOHCFWigZ+GoeqQsYSpx1qIZcgrTThTH
         Z1GA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532RSVKPT3ST1QsUqeOtlTKhr6cRUDc3AgKRmDrLoixii75AzQlC
	ytZe+bDLmgE0czeSBpP0598=
X-Google-Smtp-Source: ABdhPJx7KVkcm0QqFn0xzjyZwY9xsrQ7b5ARn6uekOtsuXaxZnC1p+Fzybk6ZNUfIGM32ijSp19Ckg==
X-Received: by 2002:a67:d601:: with SMTP id n1mr20271676vsj.2.1600380991075;
        Thu, 17 Sep 2020 15:16:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:7d88:: with SMTP id y130ls199559vkc.5.gmail; Thu, 17 Sep
 2020 15:16:30 -0700 (PDT)
X-Received: by 2002:a1f:9cc9:: with SMTP id f192mr9587388vke.15.1600380990552;
        Thu, 17 Sep 2020 15:16:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600380990; cv=none;
        d=google.com; s=arc-20160816;
        b=qS7qZXAutFP2Eu6DUQIrnrhY5UCnO5IqIqISgKVC9wwCiHJodIiKfuRXkphUFPqht3
         4ZGwetG3V5e8HVZnHPQO5DqZSbDtUskAmm8T5IxZN71yAdTDXsW+5tIQ6BEP/rqzjNvO
         qC0ZWVdB6KhtJ7Meabz1Q5vOrlfoKhoscCiR7fTaTEuIPV9dlxTFK/48WC5nDSG/Kqgt
         EdVh8/jMdZ8DZqibrowM160iXs1EzqjFfYyFGtPE47wqeGhBfst0D/JWMrWnO//74c3x
         he1EqutQ2o3cfRvcCK8mWv1st+nMHhtUrz7vZ9dNlVPY0xyBuqjRvzPtf3I1gFFUD5wb
         M0eQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ziYgXqbocOD7j0uxO/EAGepHJEfgOW1DX4mZklNm150=;
        b=MdKaMpXhi/rv5nqqOEXdKp8BOo6LDkvQFCVb44o2uQ26qO+yPzkrmDoapk0duqMirV
         kqLz/KUG5EShNcE7BggwQSECscDG8nQM38jTsCfGUh4N21oy7YKg8QnSKODvlTowyXRI
         CQ5WYYF3XtoldTEXB7NmVorWW9vtri29HQzNf45XQdkRmplHJJZqGbw9owA1AQKSLUp+
         ZsxRYgTtHGwYS3gI2NdK1/7eUJ7Ddma4CAifXazJuu9/njHRdPMv7MyMs/blNPb6f9/c
         EWfVP7IXyLJHYN3ySdnP0ZLGIsKs+/l2dOvUI5jWbcmoeS/BPP00WAxc/AdFBg35B65l
         1TIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Dk3WOStG;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates 63.128.21.124 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [63.128.21.124])
        by gmr-mx.google.com with ESMTPS id p129si67874vkg.3.2020.09.17.15.16.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 17 Sep 2020 15:16:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of jpoimboe@redhat.com designates 63.128.21.124 as permitted sender) client-ip=63.128.21.124;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-14-E3V8NLmqPlSNE6AuXh-rRQ-1; Thu, 17 Sep 2020 18:16:26 -0400
X-MC-Unique: E3V8NLmqPlSNE6AuXh-rRQ-1
Received: from smtp.corp.redhat.com (int-mx05.intmail.prod.int.phx2.redhat.com [10.5.11.15])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 152641008558;
	Thu, 17 Sep 2020 22:16:24 +0000 (UTC)
Received: from treble (ovpn-112-136.rdu2.redhat.com [10.10.112.136])
	by smtp.corp.redhat.com (Postfix) with ESMTPS id 87C5855761;
	Thu, 17 Sep 2020 22:16:22 +0000 (UTC)
Date: Thu, 17 Sep 2020 17:16:20 -0500
From: Josh Poimboeuf <jpoimboe@redhat.com>
To: Ilie Halip <ilie.halip@gmail.com>
Cc: linux-kernel@vger.kernel.org,
	Nick Desaulniers <ndesaulniers@google.com>,
	Rong Chen <rong.a.chen@intel.com>, Marco Elver <elver@google.com>,
	Philip Li <philip.li@intel.com>, Borislav Petkov <bp@alien8.de>,
	kasan-dev@googlegroups.com, x86@kernel.org,
	clang-built-linux@googlegroups.com,
	Peter Zijlstra <peterz@infradead.org>,
	Nathan Chancellor <natechancellor@gmail.com>
Subject: Re: [PATCH] objtool: ignore unreachable trap after call to noreturn
 functions
Message-ID: <20200917221620.n4vavakienaqvqvi@treble>
References: <20200917084905.1647262-1-ilie.halip@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200917084905.1647262-1-ilie.halip@gmail.com>
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.15
X-Original-Sender: jpoimboe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Dk3WOStG;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates
 63.128.21.124 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On Thu, Sep 17, 2020 at 11:49:04AM +0300, Ilie Halip wrote:
> With CONFIG_UBSAN_TRAP enabled, the compiler may insert a trap instruction
> after a call to a noreturn function. In this case, objtool warns that the
> ud2 instruction is unreachable.
> 
> objtool silences similar warnings (trap after dead end instructions), so
> expand that check to include dead end functions.
> 
> Cc: Nick Desaulniers <ndesaulniers@google.com>
> Cc: Rong Chen <rong.a.chen@intel.com>
> Cc: Marco Elver <elver@google.com>
> Cc: Philip Li <philip.li@intel.com>
> Cc: Borislav Petkov <bp@alien8.de>
> Cc: kasan-dev@googlegroups.com
> Cc: x86@kernel.org
> Cc: clang-built-linux@googlegroups.com
> BugLink: https://github.com/ClangBuiltLinux/linux/issues/1148
> Link: https://lore.kernel.org/lkml/CAKwvOdmptEpi8fiOyWUo=AiZJiX+Z+VHJOM2buLPrWsMTwLnyw@mail.gmail.com
> Suggested-by: Nick Desaulniers <ndesaulniers@google.com>
> Signed-off-by: Ilie Halip <ilie.halip@gmail.com>

The patch looks good to me.  Which versions of Clang do the trap after
noreturn call?  It would be good to have that in the commit message.

-- 
Josh

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200917221620.n4vavakienaqvqvi%40treble.
