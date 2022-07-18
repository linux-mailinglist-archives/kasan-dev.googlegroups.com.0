Return-Path: <kasan-dev+bncBDW2JDUY5AORBG6D26LAMGQE2TO6SAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 418ED578DA5
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 00:41:32 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id q16-20020a0ce210000000b00472f361d6b1sf6375131qvl.21
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 15:41:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658184091; cv=pass;
        d=google.com; s=arc-20160816;
        b=dO2l1gTiVuoUMl9E12pkmZEppDVomMEo2D4lUIFa3ARwXJFrkRl7T3dIzKxnHBrskH
         QN+MzsmfNS7J4cbM64z2+mtoZhevQCEjxg0YCw4FuBPPN00n9hFGMJCj8Xfjp2mD2FbS
         VmPv8HxmBuSWq00aGxhfiIkt5jppKEsvhanUTNmKLBnl1KxTcs0buzVXfP1MxpupUeHM
         zfSxxJ0z8zK4QY8f9KxXlrcLkpdgbZ9Qzgc1bmw7HKd4hcmCQx3zBRhdZp5/jsjjRpJb
         wVvRvIWR4wCwmB7uddevxG3DeyzdlNgLfU4vEYyNY5EhD31JgD4jBKlxk/rqe5A0kQnu
         bwgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=h2oLLbSFKxqwTJG40+LQcoxQDH0h9hV//YD5ZV9arvM=;
        b=CvAZeB3Bt9q9CyAaXd/hjZDic/2RdsasXLAc7Cw9JNKQ/KHbAcJBj5d+Scnym/stTv
         t2gfrV+d+QNK13YF9ClE6KpUNIFg5tp2lJNOYhkovGS4o2FegX+OaUm8+Bk4W0ZFrvPP
         JJnWRCwQLomHgSigHVXKWWhj/6YblZlGviw0PJtafyAwOFhSJLU3McXC3wdvBYiZhvgo
         cme/0gcqqx2LRBMVLLmBi5sTxsxRGKTeqJzpd5O57fc0nRCgM5BImge+I7J7cGZemnLe
         wWQlHd4CoiVGcT42COkTv7eK6WGZomj2evnm0sB6nOXnSUQelTRRo54pvxxMQ2BnS8vo
         8SfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="IH/FZ8Sr";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::72e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h2oLLbSFKxqwTJG40+LQcoxQDH0h9hV//YD5ZV9arvM=;
        b=R4dOhGo/cxMMeqQ77ugEgp+PmhRL4lnd7XeVRCNL5iWpQzXzXN+yyU5n3swhWjHHM8
         PPDJjeWqajo87rDty9weTfPk8nF1jpxejWNVpsf1UMwbbTwUEV0D/uwbRDkj/Eckqaw9
         3sFndnQPURp3+KxA/ugTnhH2/ylUQSCZaQLvJ1iIb0sZHGOMoXxQKSY3fYZB4zDjafdn
         QeERUxJ1gi17u5YKL45DVT47UDGOM7nQbgbE7B2GuC9T9T5zIbRiLifRjhGuP9PHsdNF
         Hy/VvqNlAUSn0rBj7ESWNsxudKKGu8Yp82M7NyvHNgE8gyWWIIGPzXBmYeOvHanFiVlj
         1csg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h2oLLbSFKxqwTJG40+LQcoxQDH0h9hV//YD5ZV9arvM=;
        b=EYTWCuAMScc1vRFCMJdW/Qz4mSqYp8eg/fqfFN9HZoMF2BaYLv7/fhUNURAX8KA1EG
         hQVQ1vkifmz7Myq0LCEZXL6ufUjV9oRSVUgffyqtv3drozgrnodKjq+MSnYplbl7kjw4
         sYCoRwKfIYk+HnUztZDTjkVYVT/CO7zPlgmUZ3EMX0bKzFFl98WvrDfJjlyRKxAfhDZY
         BoNy2+jXbTbKw6Fuuv55LrX0NHfZ06KzrxQP6cFtGDVepWwToalfpr81Pnsb33jCAFg4
         5f4KPb+aaaPzS1uZmZI/FEd6YC1KQGSBC4+N6iu2AT8zI57HVdEI7Skn14HKn1qVxwSU
         TvQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h2oLLbSFKxqwTJG40+LQcoxQDH0h9hV//YD5ZV9arvM=;
        b=skAusKvbloR0R6MFQ85AT+qDTb5fAXDao/Q7skGhgFPC9XDBcsLUaLhp7X5ifCaTRf
         4V4bpC/BaOgkCUdUEjIfitnbrfOZ0F13ucJ6gFsO5N70PuO4NhMfPShQsGxl5FebySVp
         zoUP15a35v9RdFkVh06kEGx4RG3QXmXywsoqYP6rcOEsGT5LC8RMIDU+5ywJI7MMBxUn
         XWi2/sFluW1DrM6lrhve1JKG4ly1pIvHvt8+iXKd0Ott/nZm8A4nObX71xA/v7fgvnZ3
         ALG2d/SjU25tpZCrU3glQv5XTaCdZicrOVWs861zpvGwQo+p7PccM8jAkiMy62lF8Foj
         6TpA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9dvvSmMKchILApadUDxw8Gj+RP0xof7qGs7c7ktg/sGKO7uLEs
	J2jSP/AXbdgJ0IvFJvVOQ/o=
X-Google-Smtp-Source: AGRyM1vszq/xnIZ3YihbgLfshJ58GQM69mbWN8/EbfqEhSS5VOpe4h4RQEMPKp2wWEpNaGowowIG0w==
X-Received: by 2002:a05:622a:1002:b0:31e:f2ff:e3fd with SMTP id d2-20020a05622a100200b0031ef2ffe3fdmr4174931qte.304.1658184091103;
        Mon, 18 Jul 2022 15:41:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:8c4b:0:b0:472:f0e9:6017 with SMTP id o11-20020a0c8c4b000000b00472f0e96017ls697704qvb.10.-pod-prod-gmail;
 Mon, 18 Jul 2022 15:41:30 -0700 (PDT)
X-Received: by 2002:a0c:e20a:0:b0:473:4584:7f3e with SMTP id q10-20020a0ce20a000000b0047345847f3emr22881648qvl.121.1658184090640;
        Mon, 18 Jul 2022 15:41:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658184090; cv=none;
        d=google.com; s=arc-20160816;
        b=rZTUbaJBhoCDSoAFLACBL8OkHn01Lr5rZ4i77lGGFPKfve14ylGd17TutWLVTXKrCd
         KRXHa9bZys0PW/RcKHZN9L1kxCSiTUyzdjG3e0z/Uo4o78sbpAa2NiaTOC1KqElGLYrP
         zgboCbNfTRaM2k5AUTQaN5cnBS0M0hmcYezGgGkzfeIf6M31t6FBn+bOzYZwNWuvpMem
         KetftaaRYyLCLWQi+gnDop8IpVlOuYRUX8CdNKQigbwjGEa2JdcxwwtXLcYx4ViF7Kl5
         ZIJk9SsS7KUA1Y6BwTbPCGS5Sq/e1zXpS+TfybIpUnousklakO7+j6tjNocOl4T5G83J
         9rdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ISQEQ+fIU3xAcRWcqutk61dQJfgUByc+o/p0/o9VaqQ=;
        b=lq2vB7mKcNjs7ptXyMvbOlWOr/4TtUnaPZ4Gev+g/5RpttOg3Z8O4x9sXA7T+ynk16
         OwBtDskN70Q3oQFL236qcBeSfaf8D2Zsgq2Th8tvXMvQOiRcJovR8Ot6RxnsjvHypU3N
         tksj8Vp0QZSh8Yo60ic4Py8zOS/bXBEo2UB9dYWkB+XaJjqKUpim7shK9+JKPtRceTdQ
         IIKtYlHV7P4fREE384RbxfiAbvgK/Zvt1VsKSswyLREF4cpFgIQAMvYGHes8EKG9Mfji
         HzIFFWnDbxesPAyVKLk8iAdbxLm8C079d3etf/8kRgPkx5stBPzavpUrIeb9Y3hUUjgF
         GNsw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="IH/FZ8Sr";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::72e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qk1-x72e.google.com (mail-qk1-x72e.google.com. [2607:f8b0:4864:20::72e])
        by gmr-mx.google.com with ESMTPS id f17-20020a05620a069100b006b5fa3b62dbsi58219qkh.6.2022.07.18.15.41.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 Jul 2022 15:41:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::72e as permitted sender) client-ip=2607:f8b0:4864:20::72e;
Received: by mail-qk1-x72e.google.com with SMTP id c24so4421621qkm.4
        for <kasan-dev@googlegroups.com>; Mon, 18 Jul 2022 15:41:30 -0700 (PDT)
X-Received: by 2002:a05:620a:2807:b0:6a6:6ef1:fb9d with SMTP id
 f7-20020a05620a280700b006a66ef1fb9dmr19234367qkp.146.1658184090436; Mon, 18
 Jul 2022 15:41:30 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1655150842.git.andreyknvl@google.com> <11a7bfb5ed5de141b50db8c08e9c6ad37ef3febc.1655150842.git.andreyknvl@google.com>
 <CANpmjNMTb4cxizfb5Xzy979jCA2_BMio6W4k1wZivKnu77RKVw@mail.gmail.com>
In-Reply-To: <CANpmjNMTb4cxizfb5Xzy979jCA2_BMio6W4k1wZivKnu77RKVw@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 19 Jul 2022 00:41:19 +0200
Message-ID: <CA+fCnZeq8bWKcQ5fCYuXCvReDJjv+SKcaFu-DPO==W3XPRUm3w@mail.gmail.com>
Subject: Re: [PATCH 06/32] kasan: introduce kasan_print_aux_stacks
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="IH/FZ8Sr";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::72e
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Fri, Jun 17, 2022 at 1:35 PM Marco Elver <elver@google.com> wrote:
>
> > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > index aa6b43936f8d..bcea5ed15631 100644
> > --- a/mm/kasan/kasan.h
> > +++ b/mm/kasan/kasan.h
> > @@ -265,6 +265,12 @@ void kasan_print_address_stack_frame(const void *addr);
> >  static inline void kasan_print_address_stack_frame(const void *addr) { }
> >  #endif
> >
> > +#ifdef CONFIG_KASAN_GENERIC
> > +void kasan_print_aux_stacks(struct kmem_cache *cache, const void *object);
> > +#else
> > +static inline void kasan_print_aux_stacks(struct kmem_cache *cache, const void *object) { }
> > +#endif
>
> Why not put this into one of the existing "#ifdef
> CONFIG_KASAN_GENERIC" blocks? There are several; probably the one 10
> lines down might be ok?

The idea was to group functions based on their purpose, not on which
mode uses them. Here, kasan_print_aux_stacks() is related to printing
reports, so it goes next to other such functions. We could rework the
order of functions in this file, but I'd rather keep it as is in this
change. Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZeq8bWKcQ5fCYuXCvReDJjv%2BSKcaFu-DPO%3D%3DW3XPRUm3w%40mail.gmail.com.
