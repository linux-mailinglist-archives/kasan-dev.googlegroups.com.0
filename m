Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBTWQUSHAMGQEFNSHMYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 95B1347F9CA
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Dec 2021 03:43:27 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id y2-20020a056e020f4200b002b4313fb71asf9108361ilj.18
        for <lists+kasan-dev@lfdr.de>; Sun, 26 Dec 2021 18:43:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640573006; cv=pass;
        d=google.com; s=arc-20160816;
        b=lzsTXMXivecpCLqq9QP00Y3Q1EVA87lUXepfu2ye2Kz43nFwG3Bv4INHd2z0jQSFIh
         AiJ59F+RJoRskmoO6Q8QPldXKzzcgReHY4+Y3t4UanrvYagHD9YLYhwdFEpFMO0iN/wJ
         4UY8Pbbg+x2Vzg2hGYz8Ghyj5WFquCbXCtAlN3HLyWOOA0dUWzky2HHDOvzBtEohm0Xm
         dByeWmtMooc0NQCQljlTwDe76v6EzqAYPFlH+AA2QwZb4twI2j7vObrKWnWiUq2wzluL
         HN7dLmA1EVrxau5UWp0G3hr/hBEFJotxMWKZbxW8GSsvtTvGR5PkaYdmqeWJUgeg3+8N
         nUuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=ip8JmXIDZWbzwnrUeH5a9S4etsNTLeuioz/se0NNaAk=;
        b=HzswowTDFsMUUR+1JmPZO4wHlwdCAiTWnzEyX9TFK3BMDbgJKAxG0blR/+zBq1jyBn
         YlnanIZi1gJB3RGAXJ9mrvwhMM6M8oeqEeJN0FbDZvIZhb0aHW2q/I3jo3HHAdUiBQmk
         liFQjD/GJF2fKM+0m+I9KuHWFRtSwcrCa2kHHdO2rZdLTP9q+KsWovyaVIBK/QS/G3Fz
         URi1xjsLB+xErCZO1iezd03C78BGsZ0/7m9s7adt5mgUSAL5PtT4PPoNGJexiqUr3HyK
         Eu8+sLsD2aZzVOdgz8mvBohbSJcpotMnj55feUdOob8sam36Nq5m36j/3I3meEOqB0Ol
         j1FQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=b6Cjg8ED;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ip8JmXIDZWbzwnrUeH5a9S4etsNTLeuioz/se0NNaAk=;
        b=Qi5sTT50ENBs3wfH0YeJzbRaHU42OZAYqYWJnuNrP0zPEDLZXrNB7bBE5V//DWMT+x
         FeUDwWjDDV8NtyAClHxqM0tWSMXgJDhJmAcQMSIBTQtkUfESba9P86+4THSY6QdtP0M/
         BSOf2tKNWYpzndT7z4g0sBEbbgVZr/hZ+rJUaIj6hJiVQLKGcnw+CuuBIkS7JIuo29EU
         ZeURbKXVGIsth4UYeec+ltAvuUEj558D1lFWXJLSKDjBarV6WjAJBK6MBpexAQxzoRqV
         vV4YeA/gb4rDukhz1QMjUr6MbtlgxMVPV762ipaFuThakngMb4U6DevU7SYrkjxyHEmx
         PFSg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ip8JmXIDZWbzwnrUeH5a9S4etsNTLeuioz/se0NNaAk=;
        b=fx5fkuaAZ79cnxqYnyD2rvrbtRMivDHSgg6ryGd5Uxn/z2/lqhJnbNV96NFUNkMgl7
         r5Dwvui5ToCPydsQJJCk80cXKV9wktJzH517y3isw/d5CYTQuQjz92UslADD0CwcOgmJ
         um2ibo0s5FViRi5LgwhKpJY6Smt7BcXBu8O7yEej3R84n3lUWnlp1Cneoim4iPBSMaeY
         jxzHR1WHEaVVIi9w/WnZaAWjcOlTTgiDPUdtbUjHfw2D1AdfvIoPWOmP8J+vkH/+ruji
         aAwzbML6sA4SYh5IkQNP/GURpcooqwBMAQtWKGG4ArKDLHqaY+8od1N/Ozq6CbKF+Krj
         QSdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ip8JmXIDZWbzwnrUeH5a9S4etsNTLeuioz/se0NNaAk=;
        b=3AeA2WlNX9lZg03QEdbUG0n78Ov6lzy+ttyDgKg+aRWeIGsvjvmp3QQBXtLEmUvADV
         ZnQJqna6E286lJdTo7tIEABKqOuZN+Xbl3ugNYE7BCGTpNvsE/07UGN0ycMFmAV1VgHC
         +E3sZMBbFB1zgXzjCCZWPPCbM4WmcfbtGyQIueQA+yg1TdYZthTINBJAVhuqYcJGLBVQ
         1Nkk47BSHBnoqLmvETtHsUvLof0Wjs2K3qItR/Iq3DpodmNELj9izjlzXdZ2jbAFmkw7
         /4CZ7pDSK9C93nSDvcxLut8RuC1dc9V59DEcxtJa3aCnuAc/TJc/lAOyhU4WLP8ZAZcw
         RMEA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ZSZJw8kPatHXpzKlSW1jl5ehbMC+TunrmXBMXL/QAZ+W+lt0y
	2fSDtdy8CtdKU0zqbkSB6PA=
X-Google-Smtp-Source: ABdhPJzh/9ocjIlDqfwyRyUY1IpcWwL443Gl+QNtrjq3wRkJF4qUCjUkOA9CGwXaG9oJAkq7OQjObw==
X-Received: by 2002:a6b:f403:: with SMTP id i3mr6398769iog.83.1640573006339;
        Sun, 26 Dec 2021 18:43:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:2a02:: with SMTP id w2ls1976981jaw.1.gmail; Sun, 26 Dec
 2021 18:43:26 -0800 (PST)
X-Received: by 2002:a05:6638:1693:: with SMTP id f19mr7481608jat.300.1640573005996;
        Sun, 26 Dec 2021 18:43:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640573005; cv=none;
        d=google.com; s=arc-20160816;
        b=IcbZj71l1fIdYQlcpOg1oDA7sziKScBh+vHbei5cFoZtaB1c1fKlMHInxpD6V62gX/
         zS3IhrTMvk5hdWtBp6zzJuoFWtddU2+temjh5cIjBaQn5XIZa6e0vgYOz0yzgDsMsunN
         x0kqIx8tA2olT/PopfDaSZpPNw310UE3sxkiXQcTBR6EiN7x60DunjIrrVjHNWdZCCJR
         JFyQx5iQn/i2RebY0aefPgER/ThQBsfrQbTmnqCXEW4+diDKmCgcuQF6PojOcRS0e5/l
         Lx10BZcspoCc5EHFunO4GXGkz3aboFvDSAC5FyU42Ur6n+fv3LGcwvsstCO8UHhUZkuE
         JPUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=sbWmY9NIBHJbspqdt0/iFybWiUNO01ZpzPEk+bSzcIc=;
        b=XdkDa+CqHUel5yZBq+4+RE7k5dNKVjFj12UqcI49INEdW056I1ITQabkw5VGk2Whns
         vKLxLktEsCx4q2qimpo4LiG4Zkay2B5lgfqJYNxV9JZqC9ZJRc2HGNwaYxzSBHmgVpTX
         4p+Z8QOprMK7nSA04x6u/gXAJrcWWbHnlR2Ci4Uf4nanXRjQLK9vWLnl1OclLjZuEBZ3
         CsiJ9V0a0prr2wPirlpwO56j1uoO0343Xkm6lwRSKbOOJav8yYhh555ENg28mQH+lWPH
         z+e7U3DM0Jt+2Yxc+A+NNW26NG2kv+bjJFPAEM49TWBCu4UelRI29NtPLZ0T6Cgl8vwf
         B3Gg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=b6Cjg8ED;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x630.google.com (mail-pl1-x630.google.com. [2607:f8b0:4864:20::630])
        by gmr-mx.google.com with ESMTPS id g1si489850ila.1.2021.12.26.18.43.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 26 Dec 2021 18:43:25 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) client-ip=2607:f8b0:4864:20::630;
Received: by mail-pl1-x630.google.com with SMTP id m24so10476829pls.10
        for <kasan-dev@googlegroups.com>; Sun, 26 Dec 2021 18:43:25 -0800 (PST)
X-Received: by 2002:a17:90b:33c6:: with SMTP id lk6mr18709354pjb.70.1640573005467;
        Sun, 26 Dec 2021 18:43:25 -0800 (PST)
Received: from ip-172-31-30-232.ap-northeast-1.compute.internal (ec2-18-181-137-102.ap-northeast-1.compute.amazonaws.com. [18.181.137.102])
        by smtp.gmail.com with ESMTPSA id s35sm9767113pfw.193.2021.12.26.18.43.18
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 26 Dec 2021 18:43:25 -0800 (PST)
Date: Mon, 27 Dec 2021 02:43:15 +0000
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
To: Matthew Wilcox <willy@infradead.org>
Cc: Vlastimil Babka <vbabka@suse.cz>, Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Pekka Enberg <penberg@kernel.org>, linux-mm@kvack.org,
	Andrew Morton <akpm@linux-foundation.org>, patches@lists.linux.dev,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>,
	cgroups@vger.kernel.org, Dave Hansen <dave.hansen@linux.intel.com>,
	David Woodhouse <dwmw2@infradead.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	"H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>,
	iommu@lists.linux-foundation.org, Joerg Roedel <joro@8bytes.org>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Julia Lawall <julia.lawall@inria.fr>, kasan-dev@googlegroups.com,
	Lu Baolu <baolu.lu@linux.intel.com>,
	Luis Chamberlain <mcgrof@kernel.org>,
	Marco Elver <elver@google.com>, Michal Hocko <mhocko@kernel.org>,
	Minchan Kim <minchan@kernel.org>, Nitin Gupta <ngupta@vflare.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Suravee Suthikulpanit <suravee.suthikulpanit@amd.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Vladimir Davydov <vdavydov.dev@gmail.com>,
	Will Deacon <will@kernel.org>, x86@kernel.org,
	Roman Gushchin <guro@fb.com>
Subject: Re: [PATCH v2 00/33] Separate struct slab from struct page
Message-ID: <YckoQ7tkLgFhJA7u@ip-172-31-30-232.ap-northeast-1.compute.internal>
References: <20211201181510.18784-1-vbabka@suse.cz>
 <4c3dfdfa-2e19-a9a7-7945-3d75bc87ca05@suse.cz>
 <f3a83708-3f3c-a634-7bee-dcfcaaa7f36e@suse.cz>
 <Ycbhh5n8TBODWHR+@ip-172-31-30-232.ap-northeast-1.compute.internal>
 <Ycdak5J48i7CGkHU@casper.infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Ycdak5J48i7CGkHU@casper.infradead.org>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=b6Cjg8ED;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::630
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
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

On Sat, Dec 25, 2021 at 05:53:23PM +0000, Matthew Wilcox wrote:
> On Sat, Dec 25, 2021 at 09:16:55AM +0000, Hyeonggon Yoo wrote:
> > # mm: Convert struct page to struct slab in functions used by other subsystems
> > I'm not familiar with kasan, but to ask:
> > Does ____kasan_slab_free detect invalid free if someone frees
> > an object that is not allocated from slab?
> > 
> > @@ -341,7 +341,7 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
> > -       if (unlikely(nearest_obj(cache, virt_to_head_page(object), object) !=
> > +       if (unlikely(nearest_obj(cache, virt_to_slab(object), object) !=
> >             object)) {
> >                 kasan_report_invalid_free(tagged_object, ip);
> >                 return true;
> > 
> > I'm asking this because virt_to_slab() will return NULL if folio_test_slab()
> > returns false. That will cause NULL pointer dereference in nearest_obj.
> > I don't think this change is intended.
> 
> You need to track down how this could happen.  As far as I can tell,
> it's always called when we know the object is part of a slab.  That's
> where the cachep pointer is deduced from.

Thank you Matthew, you are right. I read the code too narrowly.
when we call kasan hooks, we know that the object is allocated from
the slab cache. (through cache_from_obj)

I'll review that patch again in part 3!

Thanks,
Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YckoQ7tkLgFhJA7u%40ip-172-31-30-232.ap-northeast-1.compute.internal.
