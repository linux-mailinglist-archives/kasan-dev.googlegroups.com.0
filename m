Return-Path: <kasan-dev+bncBCV5TUXXRUIBBKMZ6X2QKGQEH4B3CJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 33B831D31C6
	for <lists+kasan-dev@lfdr.de>; Thu, 14 May 2020 15:50:37 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id m9sf3468667qvl.18
        for <lists+kasan-dev@lfdr.de>; Thu, 14 May 2020 06:50:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589464236; cv=pass;
        d=google.com; s=arc-20160816;
        b=rJYce5+i4es0Oi7+efg+OB/n0iYxnjagjur/PHDofMvn5THdIY1VeTpFU9S6MJfBWW
         aQhBt8Hfb70Adm13Ow23kGfTxHPAF09MEemdQt939Mg7xeBG1b0QB5zQdqftC4JkgLiN
         K13pppPdeeGzuXqIvqUEeDy4OdHOzZBQzGtvKkV9VCpJRvsVfDL8AQS+VeSU2eNF3ZJ2
         iCIF0LPhegjm01oXJdtTRrNEbBz9V4aOWJHqT/tWkcmJ3IC/HMVM061a2FBMHDOevUR/
         lb1T6qxgRJlWiZU3qjPaY7D/gfNz0IH9RxeugZNFufu0MTnOrNtntAWfUNbvBjiDGeha
         PfSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Mu8ZB02eNisFZOEFzUXcziAJa8jCAyyuV2sjO/cuMGg=;
        b=fnGIsUZQ462RyPik+YvbVOv7LmeSj61KKBJioDExGkhYCJyXYvCSeoT1tAXLoxgtPz
         1bP7/ypRgs7kv2c4pNkJoJREyifxCnphD6017VwLdtzLe+2/OLcxUR8zfxVLc7V8gBqe
         LYLAkLudi3tQCzzL8UGsu//ryVZ6w8dWv8ch/4i/I8FHHjY+IIXkYZ4fdU27VOQ8ye/r
         in7KvrrdJl2Mc/OlZGd/fRrIaL5zAYNA+dnyJQtw9wVnAlNtYHD9RgvbvsLmDvqzwfIO
         gjmcBf9/1eMn7D7ByoEwr3PXBw+F6IDzdKmJXbX+nsv8kXHl9l7DsxaGV9hFHVKS4OBb
         +FTA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b="iUT7/Jzi";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Mu8ZB02eNisFZOEFzUXcziAJa8jCAyyuV2sjO/cuMGg=;
        b=gUBiNpzAWhC73X3bDK0feqNxQ5Bxe024OJrR8hxBJZCZMfesW1lnQGD4he+GKBvb15
         IazlXT+XKTm7AYpyzdnh6ENNkx1F4cTU1p7YhTR9sUFg/h0wEFstc1GUhSrgznnWKpfH
         q0x49jg1XBTOHdu7P+gnVsB/bipNwXEzE6fa2kxc/ouqcbwHtbEnwl7DxLwD/Qj+NhUa
         /g6q36GMXWddRT8chUzS3GEnjwsLjtczL+mR+mtZ7ZdAChBtD43puUe2mf4Kxyt3CJQ2
         dXCzDRmrUagNuPT3WPt+WlX/dymyS6iA7Q3wvvReZICG+CeMG/GE0ZO9Z5NNhuXE2d9L
         VVoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Mu8ZB02eNisFZOEFzUXcziAJa8jCAyyuV2sjO/cuMGg=;
        b=WmgqOuxdlM71K8htpfJjVBdvujmUoDgse4i8w4TgVS1WUoV4Hloze82wLlxTUSxDu2
         h9FNjl8blKyo6yx01iuwZggz7zosjKwTU2BBhiyrMrf1qizp4paCORWCAIyGGgpIbxYj
         0kx654urbcXQrBQpTaC4gAXwXE5QyGRZrwALDIZJsZu8cudC6+XcV4uNWoBdvvSAGlgA
         I3iexqOaNcqCy0ojWvlCpqipkwX1dUEKETPHTDEHrv1dt0j+J6DlpKu+j/r08XQylgAo
         suqTbTDhU0iBTIUq4gVnv0MNllZeeoN26poV8960YQtt8z53RTCVsX8bI7WBtYddw3ms
         FwrQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532qXNfxqg1npJ1yNExcSwY+v3c3to1bwo2EAgBcfQOS/7vEJgzA
	XhUdvJVUbZ0ys64u7BuZyZQ=
X-Google-Smtp-Source: ABdhPJzxEmxjp0/mtaWZArQ09MhSzSy5TB/ozmZYHSwVHdxX4k5iwh86Chcyg+nWvyc01T8pSI6cqQ==
X-Received: by 2002:ac8:7606:: with SMTP id t6mr4312418qtq.331.1589464236134;
        Thu, 14 May 2020 06:50:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:8061:: with SMTP id 88ls913366qva.10.gmail; Thu, 14 May
 2020 06:50:32 -0700 (PDT)
X-Received: by 2002:a05:6214:7cd:: with SMTP id bb13mr4940526qvb.17.1589464232752;
        Thu, 14 May 2020 06:50:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589464232; cv=none;
        d=google.com; s=arc-20160816;
        b=Kvb2rIHPuDR/RvmxYQ37ThsG+YPz4OOZUzRZ1gcVWMLbfmbF/2BZ9C+LgTQ5YimoCl
         PiESGS0yoxxcpCj2/zhxg6pRDYSX35nWdRvokRXen+grj7qoOiU4nX1cpMfMGwPeiLkh
         yFHZdlJDXyGpfKRqqaPsilKoHAdMPtsOlGrBwIj/A0URFZ6RkiJoGrmrUijKSx+zMbUV
         cdBkRrxIyoAXJgJF2qbed0CzajmtWnTTtjbDbGDgchwY4kQW49xm8LY+DIZiUWgYST/G
         VSev9o0iZLM7+yE4xbDu7nMey60C3XU+gVWqwOSmMThRgGGFhoVNQT1hF6hBYXuC3BWE
         MQRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=oUb9XRa4HSf+di+9adEfNnhbqfuLOkGDaR9A8N50SmY=;
        b=Vyd//8Rrpow7rZ+vQCKuDVxfsmTftm3Hqqoqyfi5o5F6g8VcAiL3exhLrMsgnieXgh
         kU3n3vaJgsKSP4TWred7ehBbUAFnHd8AuZcwsiVcA+Ufr2f6w+2WCguUc7C67tpQHsPX
         8PU16bENBui8geuen961MORNPPuasVk6SF1UfERnjXwHnK2CwoFTluja/PHrGh4VsKJq
         mka7Q1KrQ0pN1i1B5v8JfLwymxeYQLdEFdAvbt43opQ4zPVrw/Oa5gpbRVIwIfXBNjOl
         P/4xLYyh6KaciUXNOcQNpndvL7Z5wnnNJWvvqYU/2aNoq1u/kPO3s5EElTuGIzCh3Y0u
         q3zQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b="iUT7/Jzi";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id w66si231471qka.6.2020.05.14.06.50.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 May 2020 06:50:28 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jZEFm-0000C0-Ut; Thu, 14 May 2020 13:50:27 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id A7B46301A66;
	Thu, 14 May 2020 15:50:25 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 944742B852D66; Thu, 14 May 2020 15:50:25 +0200 (CEST)
Date: Thu, 14 May 2020 15:50:25 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Will Deacon <will@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Ingo Molnar <mingo@kernel.org>, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH v5 00/18] Rework READ_ONCE() to improve codegen
Message-ID: <20200514135025.GZ2978@hirez.programming.kicks-ass.net>
References: <20200513124021.GB20278@willie-the-truck>
 <CANpmjNM5XW+ufJ6Mw2Tn7aShRCZaUPGcH=u=4Sk5kqLKyf3v5A@mail.gmail.com>
 <20200513165008.GA24836@willie-the-truck>
 <CANpmjNN=n59ue06s0MfmRFvKX=WB2NgLgbP6kG_MYCGy2R6PHg@mail.gmail.com>
 <20200513174747.GB24836@willie-the-truck>
 <CANpmjNNOpJk0tprXKB_deiNAv_UmmORf1-2uajLhnLWQQ1hvoA@mail.gmail.com>
 <20200513212520.GC28594@willie-the-truck>
 <CANpmjNOAi2K6knC9OFUGjpMo-rvtLDzKMb==J=vTRkmaWctFaQ@mail.gmail.com>
 <20200514110537.GC4280@willie-the-truck>
 <CANpmjNMTsY_8241bS7=XAfqvZHFLrVEkv_uM4aDUWE_kh3Rvbw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMTsY_8241bS7=XAfqvZHFLrVEkv_uM4aDUWE_kh3Rvbw@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b="iUT7/Jzi";
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Thu, May 14, 2020 at 03:35:58PM +0200, Marco Elver wrote:
>   4. __no_kcsan functions should never be spuriously inlined into
> instrumented functions, causing the accesses of the __no_kcsan
> function to be instrumented. [Satisfied by Clang >= 7. All GCC
> versions are broken.]

The current noinstr annotation implies noinline, for a similar issue, we
need the function to be emitted in a specific section. So while yuck,
this is not an immediate issue for us.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200514135025.GZ2978%40hirez.programming.kicks-ass.net.
