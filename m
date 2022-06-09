Return-Path: <kasan-dev+bncBDZKHAFW3AGBBIW2Q6KQMGQE6O5IIQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A325544CA2
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 14:52:52 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id d67-20020acab446000000b0032ae7767585sf13899234oif.6
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 05:52:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654779171; cv=pass;
        d=google.com; s=arc-20160816;
        b=UZVuZHIcvBbT107WuEWFStlPNg/QSriO/n8QahDEk8bRQSNzhG5erUWcp1bVyCtvPJ
         QcnKW/xb5P+rtZcSGw0EZkj79I8H1KkdglhtXDJ/4p2eBcduswU1PAq3JkRlpM7eRh8m
         BvsUQaX+VFXTbnBIKheSctfUzxRLOP24XTfOLppyDeAq4whP/Of2vF096GgFDnMeuXVi
         QcTsAGbP+KKqz3IOgnuP/VErz1JLGi4V1IqE5sG/yelhTkDUGGyP2ChHVareFNHSnL5g
         Ct2gIOPf56UJVOxUgY5dVszqr7rFd78xGh6ESEU5y16KiH0iO60N8T/Gs0pD/pFwfQKj
         ftjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=/t+/7C2Egm4kkqU+bleI2ftnCP70bqEonZxhitDjXQ0=;
        b=NDWHCvb7W/SEGex19czpAouvj175yJN6GiSgovLIRhgBcq577oiBzmVU8nJjt+G9vU
         uewmruyvF6iOKGJ+yWqtAgfVnS+8bnbC+kSQKFaFT14R5ETreJ5tyapllsfRSNFkVuVY
         Gea54NSassTfW35QUotaPjWBuo/IFWi1nSwKJuG5ttPQ+68rFLOl1GeM5b5nANCQ63lx
         fm6QnpLZaynm1UBH7CTs+cn8EahcyZoS1OmJVBD+B/TSGxnsbWfM+h9F/a+whpX2mmQO
         KlyVnaMxIre/cGUKhEjVMsRFZ+xMftSHbCX7AiSDpY3UANL+qMIwvxVR9JvVFoM/9KVK
         VVTg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=hn7rTMy0;
       spf=pass (google.com: domain of pmladek@suse.com designates 195.135.220.28 as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=/t+/7C2Egm4kkqU+bleI2ftnCP70bqEonZxhitDjXQ0=;
        b=W/PmM8bSu68awo9faSQlZg9uZNbFuzbjaBmTPOytNLXpau+nBzR2v4KJlS5XevGVcf
         dLscoJpVi3nWO0vygdrd9KFJkMraSae7NqPcii8rwmFkhFUeY/XIiRdHJP1jcg04ihZA
         XurjJFJgdQzduAOjJJH2EpU6gTAsQUOa9cAjC9CUhw4Y3mfqljL46JA9q4CkIMyIbvW4
         cilbdntC/dyVje6ujdiVlGbqXc6iENSvcLIiA7t65eXCnPa+Uqw3ecth0DmDbTDmpQEb
         CH6/bTnM5rSx39+7AaAi+OzMOPSZEO60tE+FWubWutqoYKR6TUItMV4fCnaAFLq9TPdG
         tEYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/t+/7C2Egm4kkqU+bleI2ftnCP70bqEonZxhitDjXQ0=;
        b=yCmIzSn9X5PTpMCG7j8rYPvFbaWnXOqfwfeijIRsKs1gz402qT1Re5q5GaXJLZN5OD
         tGRIa/9vqRunXzqDKHReJmxxnE9IF+w309oJ6oTAjqGNbSPAOeZZZKIRlt1TEu3IM4Dv
         Uk/W0CucqE3an52qwaIBCELluCK/ROkptJokfHkcrxNj1Kdl/1iO+X7q5We6e03jFagK
         3CPIJ5yvoYWFOy+HQeMTnM69PdvhTIK/PLWUC0Xma9YCpdB6vr2Pe96vV5sCz/Az+1lK
         6qwqjFbLRh9wXXQytdjcisRI4uyfdJnBjYrqBycM2O8rFguFJlD8b/f6J3ko3978X15g
         b7+w==
X-Gm-Message-State: AOAM533NhHWSUGDFlE6SYwX67R5gKTuNxm1/Sp15QfuqPWalXHE4C9rj
	8uvypwwKzEe2yM6fFq4qdHQ=
X-Google-Smtp-Source: ABdhPJyDOMF52seGqVFwtKxjveqiIIHhLwdjNALo2Jjb8/PvSY7o3VDWuoFwhDYyfAxWc6qkGffpkw==
X-Received: by 2002:a9d:6c0b:0:b0:60c:ef2:5f37 with SMTP id f11-20020a9d6c0b000000b0060c0ef25f37mr5088349otq.330.1654779170966;
        Thu, 09 Jun 2022 05:52:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:2224:b0:32e:c693:1736 with SMTP id
 bd36-20020a056808222400b0032ec6931736ls2614586oib.7.gmail; Thu, 09 Jun 2022
 05:52:50 -0700 (PDT)
X-Received: by 2002:aca:a9ce:0:b0:32e:d0b0:44f0 with SMTP id s197-20020acaa9ce000000b0032ed0b044f0mr1526209oie.230.1654779170585;
        Thu, 09 Jun 2022 05:52:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654779170; cv=none;
        d=google.com; s=arc-20160816;
        b=s0IbDDWd9ncnrTt8BuCuWnkt25zitm6I+7lIWsj8SfvPzR+a1Z8gsxT5yOV6B6uIBe
         LNyIXqhSAoKIiScvayA6yQLB+z+LDDocblbzE58jawcdBf4b/c9csZNr31qVXOs4Wwsi
         F5VwCMQGDNwzX43DpRKlPmeuChBz617oL70M8iwaKNRHc0/yhfje85nIHebGttCf/+Yt
         F4KqN8cFsd2kaIPR0IMRZ0rZgm5MswKpf6PgAqGP/LcABQTCNShVcQ4vUXb32whakdNl
         DUN6VY/9ot9ulkh2e5xtBUgTG6pHCLyQdUq72Oq5HKYpeUIQCGpIyAd2Zk+KAtgbykKW
         u6qg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=gAVJbG/BIIN8NJYQzbcQF6blONkojsp0TRzSyE1rwgY=;
        b=zo0jSRl1VuuG6x5SG5saGoaDdsGUIEyxWuS4XCKrsVOHj5qPPHM9PB+vIFVIEXpP26
         5yB0cGNffNJUohpzxEB3lGrSC/hyuT4oNgAq1JV5jqUC7E1fwcwp7qTgfRbW+Sea3e4M
         eW29Ki4sMA2yHMA134YFcZ0poCZgXs+jwKi3wmmJRwFRff+QV2v+6H0sChBmbk7+irVY
         clLYoyQTDg4mr1t5rthKDzFG+jbHLKxdLP8A/MoCd+EHQmyD3M3rgaUpLF9EoQVssn+O
         x8ZWwvdfinXj164hp7pbVAvuqXlwf+ToMsD9iTSrWnNjJqaA0UVtT1sbSEeyxCuUO7QZ
         4I/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=hn7rTMy0;
       spf=pass (google.com: domain of pmladek@suse.com designates 195.135.220.28 as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id pk10-20020a0568704c0a00b000ddbc266799si1632790oab.2.2022.06.09.05.52.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Jun 2022 05:52:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of pmladek@suse.com designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from relay2.suse.de (relay2.suse.de [149.44.160.134])
	by smtp-out1.suse.de (Postfix) with ESMTP id 59F5921F23;
	Thu,  9 Jun 2022 12:52:49 +0000 (UTC)
Received: from suse.cz (unknown [10.100.208.146])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by relay2.suse.de (Postfix) with ESMTPS id 023012C141;
	Thu,  9 Jun 2022 12:52:48 +0000 (UTC)
Date: Thu, 9 Jun 2022 14:52:48 +0200
From: "'Petr Mladek' via kasan-dev" <kasan-dev@googlegroups.com>
To: "Jason A. Donenfeld" <Jason@zx2c4.com>
Cc: linux-mm@kvack.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, John Ogness <john.ogness@linutronix.de>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Geert Uytterhoeven <geert@linux-m68k.org>,
	Geert Uytterhoeven <geert+renesas@glider.be>
Subject: Re: [PATCH v2] mm/kfence: select random number before taking raw lock
Message-ID: <YqHtIGI7ueuI/ovx@alley>
References: <CAHmME9rkQDnsTu-8whevtBa_J6aOKT=gQO7kBAxwWrBgKgcyUQ@mail.gmail.com>
 <20220609123319.17576-1-Jason@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220609123319.17576-1-Jason@zx2c4.com>
X-Original-Sender: pmladek@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=hn7rTMy0;       spf=pass
 (google.com: domain of pmladek@suse.com designates 195.135.220.28 as
 permitted sender) smtp.mailfrom=pmladek@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Petr Mladek <pmladek@suse.com>
Reply-To: Petr Mladek <pmladek@suse.com>
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

On Thu 2022-06-09 14:33:19, Jason A. Donenfeld wrote:
> The RNG uses vanilla spinlocks, not raw spinlocks, so kfence should pick
> its random numbers before taking its raw spinlocks. This also has the
> nice effect of doing less work inside the lock. It should fix a splat
> that Geert saw with CONFIG_PROVE_RAW_LOCK_NESTING:
> 
>      dump_backtrace.part.0+0x98/0xc0
>      show_stack+0x14/0x28
>      dump_stack_lvl+0xac/0xec
>      dump_stack+0x14/0x2c
>      __lock_acquire+0x388/0x10a0
>      lock_acquire+0x190/0x2c0
>      _raw_spin_lock_irqsave+0x6c/0x94
>      crng_make_state+0x148/0x1e4
>      _get_random_bytes.part.0+0x4c/0xe8
>      get_random_u32+0x4c/0x140
>      __kfence_alloc+0x460/0x5c4
>      kmem_cache_alloc_trace+0x194/0x1dc
>      __kthread_create_on_node+0x5c/0x1a8
>      kthread_create_on_node+0x58/0x7c
>      printk_start_kthread.part.0+0x34/0xa8
>      printk_activate_kthreads+0x4c/0x54
>      do_one_initcall+0xec/0x278
>      kernel_init_freeable+0x11c/0x214
>      kernel_init+0x24/0x124
>      ret_from_fork+0x10/0x20
> 
> Cc: John Ogness <john.ogness@linutronix.de>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Marco Elver <elver@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Reported-by: Geert Uytterhoeven <geert@linux-m68k.org>
> Tested-by: Geert Uytterhoeven <geert+renesas@glider.be>
> Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>

Reviewed-by: Petr Mladek <pmladek@suse.com>

Thanks a lot for fixing this. It is great to know that the printk
kthreads were not the culprit here ;-)

Best Regards,
Petr

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YqHtIGI7ueuI/ovx%40alley.
