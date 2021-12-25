Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBEWDTOHAMGQEAMDYZIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 3399A47F2BF
	for <lists+kasan-dev@lfdr.de>; Sat, 25 Dec 2021 10:17:08 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id u21-20020a17090a891500b001b14cf69a22sf6860703pjn.2
        for <lists+kasan-dev@lfdr.de>; Sat, 25 Dec 2021 01:17:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640423826; cv=pass;
        d=google.com; s=arc-20160816;
        b=zEKrnjlUKDT7Av+n2R5b6jLjORixAtFKAUzE0h3ZhPlHiqf8X8PgMs69W7u0gpdpBD
         ohpFm/sqSghFZEBXyh1Je9/grSuUUYqTvryWKT3N4sqoJaRKdHFmFl5Dk0widLaWAlAB
         Wi07hZraZ+EpRceR2lrqI+nWsOCj47ALtMyOGooNe3lkMtOunKlxf/Evcr1YD/b9dVOL
         tLXd0S7uUyngdWoX+UJP3eXnYsT8SAkCdMve+pTbw3l4KafQwFgvSU82v2aHAdXx6Ozh
         gmE2n45aiY2KXgoEJWydDlyGecT8rFHvdOJiwIusAyPdP1+LFZwIOQomJ88UnWcbx8I/
         n37g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=9XSsRR6VUSfMTFL45mkXoDnrCnt9KP27rARFFCovHbA=;
        b=q5i+Hm95vwS6wmev5QCmyNv1GQf4mE1htA3/Eo5UhXvAyY5MLscyj4aYPjhIUhBebI
         +ODpguvU8mM8GNBBB5Zk9/LgSIZ9qEJXUFMNrCRBrQ3vEGwb73aUqKx9b6T/o+IEggMW
         D1lEZyOaTGSr7HcNzclYlwv5LTYHgPEGnl9bJ0VMDmHfXk1Cf5EoyGSi8Ti458mL+8OR
         9YpW3TRlJQG4MkDqZwr/miBA4ZqKfgVaXrwbh4xZ8X++wjW4Adpuf6+0CS6J/XYRLJVJ
         zIm+nA4gAR5fz3pjtuGiDFEJnzLOyo5QcvC+RO8+jQZ517bqjqjxngj9R8xh0+TgVQEp
         Drcw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=nOfcDm4R;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9XSsRR6VUSfMTFL45mkXoDnrCnt9KP27rARFFCovHbA=;
        b=pf2XxUfO7Xxpc1ygghK3z05JUxK7fq9e7ZhuXNf3xGUoGT5JfS+546joebsHSiY7ig
         BOlxNuIrMnA+8ThT25aPBirK0EiwNfC+0jRi8IwpilQ4MF0RyxWmROcRytueas/uhSQ/
         udKrkOiziOtNsA9B7uJbsymzqQH9md5yizs0fVOmIq3NNi5JKYy1OSeIatN85Vvu/szJ
         E5SG/Qr3pH4SL4lRGElzfqOGN508X1lLzON+zilsB/t7HQ++i0SxmARN4IneZIYL82J9
         yiB1tQQM8UHhYvO/JIEyPkHfwTriyV/QTK95c+CI8rzrI/QsWPlVx+JM5LhOrfaebhlu
         SDgw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9XSsRR6VUSfMTFL45mkXoDnrCnt9KP27rARFFCovHbA=;
        b=OXLN1E+K/ViWoc3LITpZlApvHh/i20N3adE7jZKuU3Y/Gzk7qOH51Z+qL+pZIlHeTM
         ruFxZujdC6fuhGCAbhQKuEpTRzShvqiI0EYfUpHUtF3dfOOzRrkxFcBiTVB4ZPyK4cya
         ZREFh/klH5vB5ObQKx5JTpASgqrDhMj56fYOmOoHZC1Zrh1YQg2+TXTStMIzaGJFpZcL
         268le3q6/XBYzPjHxPyMs0eM3W6CDpKXcmgOvxNL38MIzz97nL0bT8Ex+BYPdGj9BwuB
         lphklH19szgkesHwHLGCm48pXtOvvwbRXsxZUMC+f70WApXlJJhWGoe64EGfMqAYc3wI
         w9eA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=9XSsRR6VUSfMTFL45mkXoDnrCnt9KP27rARFFCovHbA=;
        b=1n1zgqs/gOlSZr3ph2V0O6+llGQRCyzlA2ARa1Fn79mVRgL/KPibZXde38ZimFEyFp
         3u4z4rndgpDi7xspXRoeZ7bSqXKtveDdYVSqNEsXZbRxm+e565vXkXt/7NwAvErWGBAp
         xxCrE2TNm11nLG/IQXwzbl+DXJdllkzBV8umRgNO0Hn/bnIL6DYw3ZJzLojKO+llktiL
         daUJo0KLIeZieH+e2Yz+4wY69wnZXu2X7frggpQPOXYYuYQx0UTCtzSRlxsmatP+dJnp
         UB8ADKZrVdl2FHHglKfWPPSYbtxTZpqg5zdh6tDOFCa/9QzCsJhcmXv2IILU8AF+gfMH
         4iWg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531qoQtK5E11m15ZGqN90Bdh9v6d6IqNDoyuv/QQn0Ut93e1T/eM
	kDSXI57N/kfQPxeMzi80/VA=
X-Google-Smtp-Source: ABdhPJwuJLWE6CoJfP/imd48PhTkLJiszq6afe1iSXPtlTL714On1TDRjVYjV9LkbZQbAzKa3CY02g==
X-Received: by 2002:a17:903:1c4:b0:149:45fb:d6f0 with SMTP id e4-20020a17090301c400b0014945fbd6f0mr9352404plh.143.1640423826558;
        Sat, 25 Dec 2021 01:17:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:7359:: with SMTP id d25ls3788958pgn.2.gmail; Sat, 25 Dec
 2021 01:17:06 -0800 (PST)
X-Received: by 2002:a05:6a00:b50:b0:4bb:460a:fd31 with SMTP id p16-20020a056a000b5000b004bb460afd31mr9899858pfo.63.1640423825972;
        Sat, 25 Dec 2021 01:17:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640423825; cv=none;
        d=google.com; s=arc-20160816;
        b=Jo9vYk7HVz9o0nihwYkOsiJGYd67H2SV7DzB7wXhzAmDQS93Oyhrom1paGWMbbyAQJ
         W8zWr+sscgEiDKvt81BG47Ilyk1D8YDRRaAqJvZUxxmLsQWQtbkaxkpl2QNom1gKAIaM
         8/8l3oS4znsVXOuAMb+sFXjZA2Q2IWOewpKLowQcxgRA943brS+dPf8PKMxNB1ODpj/R
         zRUivaziAkWFpKy2YIkJh4xzsFBwqNqZmlrvqlARyGol2PKKUkLGtcFlEppQZFZv1Zcf
         AH6pzxUlq4ALs/OYfSrxc++PzQeI1PB8/kG4a9uAalGcYsEXDTX/uSSQBFzjmSuZ4Pnf
         bFNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=j8TrOsw0QgcOPU1it/XtIDhHHO12dds110STZzwzYD0=;
        b=HBN7tcCx3lQq1MKYIgqL8Fzy89OJhsPsqYeXzMuInO1gt5icll/MSGNcevmzjNV6Qy
         xV5fYly65PWz93cenRu639xkcU0xIe42N1ccbdGJ7uQQucc02Mkb+1fJPF26QIFhSk5w
         oT1BWrRGIfLbee49wNtbSz3whRxX9a1QSyNgPomAlUTAdt1v5LzOxprEr7yAn4k4E/pg
         VM5/EKlGkd/+MUoJy60UhgdwCY6GMEqRQWV4Nsi3czEUr8SxooNHsyXJDy5OasMTmGz1
         z/GazUjodeGzn7na9vcQ11nMVR+u/pDb5+sQc4/LkJvJ+d9DlSLTHreHdUY8BwyC9+zy
         SR3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=nOfcDm4R;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x634.google.com (mail-pl1-x634.google.com. [2607:f8b0:4864:20::634])
        by gmr-mx.google.com with ESMTPS id bc8si217946plb.12.2021.12.25.01.17.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 25 Dec 2021 01:17:05 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::634 as permitted sender) client-ip=2607:f8b0:4864:20::634;
Received: by mail-pl1-x634.google.com with SMTP id h6so4148131plf.6
        for <kasan-dev@googlegroups.com>; Sat, 25 Dec 2021 01:17:05 -0800 (PST)
X-Received: by 2002:a17:903:2303:b0:149:50d1:19d0 with SMTP id d3-20020a170903230300b0014950d119d0mr9507103plh.86.1640423825603;
        Sat, 25 Dec 2021 01:17:05 -0800 (PST)
Received: from ip-172-31-30-232.ap-northeast-1.compute.internal (ec2-18-181-137-102.ap-northeast-1.compute.amazonaws.com. [18.181.137.102])
        by smtp.gmail.com with ESMTPSA id t10sm11886406pfg.105.2021.12.25.01.16.58
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 25 Dec 2021 01:17:05 -0800 (PST)
Date: Sat, 25 Dec 2021 09:16:55 +0000
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Matthew Wilcox <willy@infradead.org>, Christoph Lameter <cl@linux.com>,
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
Message-ID: <Ycbhh5n8TBODWHR+@ip-172-31-30-232.ap-northeast-1.compute.internal>
References: <20211201181510.18784-1-vbabka@suse.cz>
 <4c3dfdfa-2e19-a9a7-7945-3d75bc87ca05@suse.cz>
 <f3a83708-3f3c-a634-7bee-dcfcaaa7f36e@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <f3a83708-3f3c-a634-7bee-dcfcaaa7f36e@suse.cz>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=nOfcDm4R;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::634
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

On Wed, Dec 22, 2021 at 05:56:50PM +0100, Vlastimil Babka wrote:
> On 12/14/21 13:57, Vlastimil Babka wrote:
> > On 12/1/21 19:14, Vlastimil Babka wrote:
> >> Folks from non-slab subsystems are Cc'd only to patches affecting them, and
> >> this cover letter.
> >>
> >> Series also available in git, based on 5.16-rc3:
> >> https://git.kernel.org/pub/scm/linux/kernel/git/vbabka/linux.git/log/?h=slab-struct_slab-v2r2
> > 
> > Pushed a new branch slab-struct-slab-v3r3 with accumulated fixes and small tweaks
> > and a new patch from Hyeonggon Yoo on top. To avoid too much spam, here's a range diff:
> 
> Hi, I've pushed another update branch slab-struct_slab-v4r1, and also to
> -next. I've shortened git commit log lines to make checkpatch happier,
> so no range-diff as it would be too long. I believe it would be useless
> spam to post the whole series now, shortly before xmas, so I will do it
> at rc8 time, to hopefully collect remaining reviews. But if anyone wants
> a mailed version, I can do that.

Hello Vlastimil, Merry Christmas!
This is part 2 of reviewing/testing patches.

# mm/kasan: Convert to struct folio and struct slab
I'm not familiar with kasan yet but kasan runs well on my machine and
kasan's bug report functionality too works fine.
Tested-by: Hyeongogn Yoo <42.hyeyoo@gmail.com>

# mm: Convert struct page to struct slab in functions used by other subsystems
I'm not familiar with kasan, but to ask:
Does ____kasan_slab_free detect invalid free if someone frees
an object that is not allocated from slab?

@@ -341,7 +341,7 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
-       if (unlikely(nearest_obj(cache, virt_to_head_page(object), object) !=
+       if (unlikely(nearest_obj(cache, virt_to_slab(object), object) !=
            object)) {
                kasan_report_invalid_free(tagged_object, ip);
                return true;

I'm asking this because virt_to_slab() will return NULL if folio_test_slab()
returns false. That will cause NULL pointer dereference in nearest_obj.
I don't think this change is intended.

This makes me think some of virt_to_head_page() -> virt_to_slab()
conversion need to be reviewed with caution.

# mm/slab: Finish struct page to struct slab conversion
Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

# mm/slab: Convert most struct page to struct slab by spatch
Tested-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

I'll come back with part 3 :)
Enjoy your Christmas!
Hyeonggon

> Changes in v4:
> - rebase to 5.16-rc6 to avoid a conflict with mainline
> - collect acks/reviews/tested-by from Johannes, Roman, Hyeonggon Yoo -
> thanks!
> - in patch "mm/slub: Convert detached_freelist to use a struct slab"
> renamed free_nonslab_page() to free_large_kmalloc() and use folio there,
> as suggested by Roman
> - in "mm/memcg: Convert slab objcgs from struct page to struct slab"
> change one caller of slab_objcgs_check() to slab_objcgs() as suggested
> by Johannes, realize the other caller should be also changed, and remove
> slab_objcgs_check() completely.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Ycbhh5n8TBODWHR%2B%40ip-172-31-30-232.ap-northeast-1.compute.internal.
