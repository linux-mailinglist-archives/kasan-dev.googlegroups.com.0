Return-Path: <kasan-dev+bncBDUNBGN3R4KRB4HT673QKGQE2G5EMIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 75D5921277B
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Jul 2020 17:14:56 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id p9sf26375967wrx.10
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Jul 2020 08:14:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593702896; cv=pass;
        d=google.com; s=arc-20160816;
        b=PokuBB6cYRgSjGObq0ZR7Jf6T7V+jVxNGdNda3VyxI2QCOolDEbleaUfWjvtaVsNAd
         hGjg2MsAKGckhSmKgDFnEFPrxDv9f0w2fz8u4BQhcqBrK9LfQp05luPzPiPYWE4wy3Iq
         PgyTbaEEA7AjSahHDgn32ckSKqp7zH5M2VRH0bJBx+mJDT3pgOXkpnU/ddiJzsc4E0Qc
         V9eXOsNOfpF1G9gdWpgRg5ptoj8zTvPvGyXUgAICctyuR5eyxih+8266i4K6AtwVP0IV
         VnwDbpxr/aAhQbDg9qQMhdrsl8MfKUuFD2EGmvmstnJOc1bzgo8vaeJANfAPr7GVKUHT
         VIGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=nshWPhaGhgx/bmR+HlVYtXpbOs6D9xPHTcYoh5nH5y0=;
        b=mBVmkyCVAVIkDyJACR7SsglpK8mViIffSXeB48jMCAdiUtd+jv0TaXMZm0u8Gl9Pa9
         3Vjwpyxf4KOfhayPteb8hlyaqQYUyH/DCgO1Ez677C+nsVlzy+Q1HYHeYml/J0lZx1kO
         Gl9pRI6dnx53jdnOS+wYu6J+1AVjUA319HyQ8rLmtLZkydkkmTe5whgeFLYjnxSfkumA
         drFxY4Lo5++d3+hCpCKq78Iyl61aCnTpMfcP47g/IdATZRulgaHcAAZxaNQpQq5dLPRu
         apTGI7eR/PesvsTUvFr3gkF5FgGpsM4CUC7qWgESA1+M7gY39Sm/f5yi5tin9SFMVqtn
         UIww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of hch@lst.de designates 213.95.11.211 as permitted sender) smtp.mailfrom=hch@lst.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=nshWPhaGhgx/bmR+HlVYtXpbOs6D9xPHTcYoh5nH5y0=;
        b=JFEv3gHV9p91d5+6/UEr2ToIk09fihTa5W3CS+hBilByzUDZC3JAutf59h/4yjJR2U
         oRwEO5MlPZSGK3WWnJ+fVz+5s/MUOf4NLEPJD6I94iN7TysU2bpd6i5jlYkG4TN5NbP2
         N7y0+RgYXuMy/el9+76K7F36OP1skf8m6dVZMOmZq9W0bDpVy0AM/0J0pPvS49XMUvj0
         83m3lLJ8UNUkDa/sMKpei0kCXYDwoq0ZZ7s9/FrbfGLaVsykgqFJgEHPjiM2XqEa59It
         on6xctN7mC5eaoo9FGbOn/AHPO6XgPEE2TxP4dgBfwhYv6n1XeGLwA9mbKH632lwI6k2
         ka3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=nshWPhaGhgx/bmR+HlVYtXpbOs6D9xPHTcYoh5nH5y0=;
        b=X2XL7frr8CrEVW5gB3dCQ+6H9pKwu2SFTKN+BGmrJMzzGCKDLmYOlPZfDt8aPLB9fZ
         H55OnsRw+NAYxGiwZcMKwBwXAfPe5qNAjkHVYjbUzbf6D6sg512Ue520DmWr1R9Xqnag
         ZUkxQGgiMRKonaNvbwGjvnXnvdYT9Qe7LeiQiukXYAP6gzsG5eq88pahnAdCJzBxnsgf
         6A8TpV+6Fm0FKIE/iPagLHayrlO3cQz7Nf4cnGHx8UwgYV7r4hmCQ231y7WImko7KFc+
         JkpKoXA59nGN+IllriVSQ/N+4cfPf5/aFMkLe/psLnEElfK82INI+jJizHesKUo1dodm
         hrmg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5313WdO8M4id34MVuDYQjSIqO/T+PIMlUibXuLhjThnd8uSN6Fcn
	XtGxaK9qp99STaflQGGK1SE=
X-Google-Smtp-Source: ABdhPJyw9BPYkM5yqr7QGlRzHGQl2QMmiA4lvaNu1QYRQWsmB4YUoc6tyCXCwgu2GUO+dwfYk2LVvQ==
X-Received: by 2002:a1c:32c4:: with SMTP id y187mr32834968wmy.79.1593702896130;
        Thu, 02 Jul 2020 08:14:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:a587:: with SMTP id o129ls3243167wme.2.canary-gmail;
 Thu, 02 Jul 2020 08:14:55 -0700 (PDT)
X-Received: by 2002:a1c:9cd0:: with SMTP id f199mr30966680wme.94.1593702895505;
        Thu, 02 Jul 2020 08:14:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593702895; cv=none;
        d=google.com; s=arc-20160816;
        b=vs8fW2fQD3puBBjQx7ZEcru9vO0ZOEVH7CivlZ84VnCGQYHvVtFmuGzyKP58JO5tvS
         Os6UA1vnhJ8Duxq8zwX9Eoc/SC6Qp2u9hS3cifPX5japY7GvP4e4sp/BeLMg53m0p8oU
         4Ik6iM/UDp7VM2mDz87OXn0f3pRY+yxwnLhcSMIcz4GdYFgd1N5OBuNt+2kizE264rEJ
         NLIx8Ell/mCda5i/Dz6fxZVC5Z0SxNYEvBQMHCNYQlNtJz57eM/mKIecwaEtQ2ngE+h8
         QBlw2GAkXDdJ3v5yBevczwOTfWN3XchR/y3IQFO10ssnwdE+3lpkUCFSOrtZ8uPttLik
         6nqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=rBbi+WfMTbIW0ORfnsl6XOnG//SEnGsZJXCBLJrVUlo=;
        b=QhjJu8kzVS+z7YJrkQyptMV/vimB8sBmEGji1jcVKSeBVGI2NlQcrJtJZMFWzesTKa
         Inh23eosoHhfvAToWAjPJiHI1slc4sLMUYngS4M+XLH9vLwT2ym5W8xHP/czogBmE7dI
         ufvMgnVJvXxr9MElH/wXavp8iybpE/+mhXPxmzPUJYPpcnPke42Tn5aBT7B3QQk+v/AL
         hBcKoE9DXKTQp4qXmeF3EAVyZrpqayXUKCAvtJMmDCIT3tU1eELbtC53Yh16JSEU2WrY
         S30tQvcU8jWuv0baddB00qHAfk0Wa0UN+cnGuPRccbDIr88I+BaPoD8e0w68pwBkqj9p
         kDEg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of hch@lst.de designates 213.95.11.211 as permitted sender) smtp.mailfrom=hch@lst.de
Received: from verein.lst.de (verein.lst.de. [213.95.11.211])
        by gmr-mx.google.com with ESMTPS id y6si455676wrh.5.2020.07.02.08.14.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 02 Jul 2020 08:14:55 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of hch@lst.de designates 213.95.11.211 as permitted sender) client-ip=213.95.11.211;
Received: by verein.lst.de (Postfix, from userid 2407)
	id 9DA8768B05; Thu,  2 Jul 2020 17:14:53 +0200 (CEST)
Date: Thu, 2 Jul 2020 17:14:53 +0200
From: Christoph Hellwig <hch@lst.de>
To: Qian Cai <cai@lca.pw>
Cc: Christoph Hellwig <hch@lst.de>, Jens Axboe <axboe@kernel.dk>,
	dm-devel@redhat.com, linux-kernel@vger.kernel.org,
	linux-m68k@lists.linux-m68k.org, linux-xtensa@linux-xtensa.org,
	drbd-dev@lists.linbit.com, linuxppc-dev@lists.ozlabs.org,
	linux-bcache@vger.kernel.org, linux-raid@vger.kernel.org,
	linux-nvdimm@lists.01.org, linux-nvme@lists.infradead.org,
	linux-s390@vger.kernel.org,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH 18/20] block: refator submit_bio_noacct
Message-ID: <20200702151453.GA1799@lst.de>
References: <20200629193947.2705954-1-hch@lst.de> <20200629193947.2705954-19-hch@lst.de> <20200702141001.GA3834@lca.pw>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200702141001.GA3834@lca.pw>
User-Agent: Mutt/1.5.17 (2007-11-01)
X-Original-Sender: hch@lst.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of hch@lst.de designates
 213.95.11.211 as permitted sender) smtp.mailfrom=hch@lst.de
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

On Thu, Jul 02, 2020 at 10:10:10AM -0400, Qian Cai wrote:
> On Mon, Jun 29, 2020 at 09:39:45PM +0200, Christoph Hellwig wrote:
> > Split out a __submit_bio_noacct helper for the actual de-recursion
> > algorithm, and simplify the loop by using a continue when we can't
> > enter the queue for a bio.
> > 
> > Signed-off-by: Christoph Hellwig <hch@lst.de>
> 
> Reverting this commit and its dependencies,
> 
> 5a6c35f9af41 block: remove direct_make_request
> ff93ea0ce763 block: shortcut __submit_bio_noacct for blk-mq drivers
> 
> fixed the stack-out-of-bounds during boot,
> 
> https://lore.kernel.org/linux-block/000000000000bcdeaa05a97280e4@google.com/

Yikes.  bio_alloc_bioset pokes into bio_list[1] in a totally
undocumented way.  But even with that the problem should only show
up with "block: shortcut __submit_bio_noacct for blk-mq drivers".

Can you try this patch?

diff --git a/block/blk-core.c b/block/blk-core.c
index bf882b8d84450c..9f1bf8658b611a 100644
--- a/block/blk-core.c
+++ b/block/blk-core.c
@@ -1155,11 +1155,10 @@ static blk_qc_t __submit_bio_noacct(struct bio *bio)
 static blk_qc_t __submit_bio_noacct_mq(struct bio *bio)
 {
 	struct gendisk *disk = bio->bi_disk;
-	struct bio_list bio_list;
+	struct bio_list bio_list[2] = { };
 	blk_qc_t ret = BLK_QC_T_NONE;
 
-	bio_list_init(&bio_list);
-	current->bio_list = &bio_list;
+	current->bio_list = bio_list;
 
 	do {
 		WARN_ON_ONCE(bio->bi_disk != disk);
@@ -1174,7 +1173,7 @@ static blk_qc_t __submit_bio_noacct_mq(struct bio *bio)
 		}
 
 		ret = blk_mq_submit_bio(bio);
-	} while ((bio = bio_list_pop(&bio_list)));
+	} while ((bio = bio_list_pop(&bio_list[0])));
 
 	current->bio_list = NULL;
 	return ret;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200702151453.GA1799%40lst.de.
