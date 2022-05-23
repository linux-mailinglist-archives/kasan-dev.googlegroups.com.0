Return-Path: <kasan-dev+bncBDKPDS4R5ECRBUO3VSKAMGQEL2U4WZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 58D7F5309A4
	for <lists+kasan-dev@lfdr.de>; Mon, 23 May 2022 08:46:42 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id l20-20020ac81494000000b002f91203eeacsf8027364qtj.10
        for <lists+kasan-dev@lfdr.de>; Sun, 22 May 2022 23:46:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653288401; cv=pass;
        d=google.com; s=arc-20160816;
        b=Gsp+De6LtUd6bAw3lbqHbqb6PmTlflOQrInykrEiviYmiAD7+xvKek2JhnTD5j4DgM
         UnXCh0IzWeA4+7FCB76sspX1CsrnaMEvRI0wcI+mstrGToL+AjJ6V6jo6SyWOj+Mz8AB
         fJQhGt3UdkX7ftCKJfJsKmT3Psixw/krB9+WacAfmYVAYPsQ0JJzxk5N1a6175+Fbfxw
         6kUbhi9kMA6ev0p/phFkqqJS6bNhNCWTjDiThHUxbmW2MZLH1XWDXoihrMk5wK/ialFK
         Thmj9BUNrsYPPzaxOxPDVohOBJMPo/OjmQTzHEWtFy1TCVpvRfjAs106Y8HfBTUxL+K3
         9Izg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ICCLs15SqZHfwd0TXAXT4tB9qLIPDgu9SkyJWuJVRGU=;
        b=06j84QbQxlJUEvyGWf74PNhzqz+ShkfJJkqbI6YT9amFV15NRY4kXq4Wz5lr4b7hky
         f498WCaP4q8IgXpRLlCOKo03BCPi6ry6R1Mr1K7RBqEm71H5z3am3vH2pcvlh07QWicM
         zZ2ieEtQldn35VtFGlmyqioIV+1lJTGQsPRC+xKei4kYmio3XQMIw+qgFsRK3voXUgxZ
         eDWTzvrGzR9vQ5kBE+E5z+lU73bdfF4KCPhu7IOQh7f/cSA/BwGV60nT+g7pVe4HDS7U
         CPews3fVLdIh/qXOxdQ1jMQ5vE4zGG3GKEAkOfN/sMIUnyIa/KWL8lNd2eaN/k+TMZgc
         t1Vw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112 header.b=pIbr7eUQ;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ICCLs15SqZHfwd0TXAXT4tB9qLIPDgu9SkyJWuJVRGU=;
        b=kWX7rypl8mVD2zKTxWfkvJF7cHLVmW816H9hM1/lFTcO2hcVUo7nZHQA1UrnxO/lCs
         9XbWylyJ4Xb64HpQZOMtLM6SiKS/SiOZvXRyrr65uxwMyjfboVcX1qCsCGh4ZBVIrNyH
         I4ll7cZvrBbhy4w0al8rxCm65IdvJg19YfOaz3asuOo0ED8flq2agwb5I6Nx9sQYr6+v
         VzN4uydxIg2KD4wnJiACMqhTcggJAhMx1q9xKuw2lAzVzdW4vgCsAGhJY0uhMmGrMrZh
         phUwv/N6w940b+UJT3Rrh1OhimhN8D33Qy7QH1hmFwUe5HKEHstS3brY1gCmCuY056Xl
         P8iA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ICCLs15SqZHfwd0TXAXT4tB9qLIPDgu9SkyJWuJVRGU=;
        b=hzH3gMAXhx0F5iS+YQTURRcKDWGz11tpUkNPiMHBoC54uf5BKTVKkekq/sKeDsCC0W
         7HA1McGdly0w1pYEGTWBIFMtffv/FKOmVPFJypCL2UIpIy1skmo/aiF82W3r2ROTHGDq
         1Cj4O0FHVR6i0rLxMCEme2Ts2UhYW1l2u/lD0X3AJKB7H2vin/m3YcmMgvH6mMDzLSUC
         bdkSQ5/evDJCpqU9/87TEfyql/ncmgmCCnis03vqAvI7E5UodqyowYz+dPoNokmAibeM
         CFln+AJGQmt7Ksr4xKGjiTpjFWKLdNlikqxvyLCRuDthBY79n4l5CPwHIg5DPGIbhbwA
         kgww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ZvxrxMGp4tw2AVvAFPxUapdCTJA8j6RENsCBJNYk+io8EA41h
	VXazavnLUUwNAwB63iCfvV4=
X-Google-Smtp-Source: ABdhPJwDqeLNS0ZbBdkr7ucfBiIy7qMVuNGu9bRSChIKP+aU1vBui225BAz5StgCBLGcEDu0T2+FYw==
X-Received: by 2002:ac8:5c48:0:b0:2f9:31f4:642e with SMTP id j8-20020ac85c48000000b002f931f4642emr4471907qtj.542.1653288401288;
        Sun, 22 May 2022 23:46:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:a87:b0:461:d538:7229 with SMTP id
 ev7-20020a0562140a8700b00461d5387229ls4843661qvb.0.gmail; Sun, 22 May 2022
 23:46:40 -0700 (PDT)
X-Received: by 2002:a05:6214:19cc:b0:461:fb6b:d408 with SMTP id j12-20020a05621419cc00b00461fb6bd408mr14044986qvc.64.1653288400863;
        Sun, 22 May 2022 23:46:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653288400; cv=none;
        d=google.com; s=arc-20160816;
        b=HHsG3z7tb+z+quV++ocrBtegdQjfQ6RflFTkH2P9jc4IerIezm1/vDoSWq3KpTCRSR
         UcXHXxvTQeVRQLaly753XGnhBByHD/pMYICqqHtm/KwdFtMoGsz6kI1pR6iJvDDFZfQW
         GttTBKWBPuxTnFWFNdLs8tuGyeYa/h1X9MZ8n49A+9xruAaTGGyTd14kZ1a2nK8xaZ8g
         SsEkgYAZqPqfciS6BVq7dh/OYvmxuZoSvqZr1j5A8gneDkvup+KW39XjoEFVZpZCtRij
         481XFppmbo1gWsPCxqyVzrCDD7mLPOgSRQ53WWfZq30EUcdnSMLazkvs6P3hNWl9OJg/
         w/oQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=X0xImzKACB8xr09/1p2KiEMME+Z8nsRkoW03SWthovs=;
        b=rQa4KG26nxmhl6Ox5TXNBFioMB2n81wj6wrWPbYNfXdZETIfCMi59reP7Z2AZX/4Qp
         NbN+OU06QoqzAcq7pIgpUCBqnyRVgKnlTsZyhHpiCxMsSx4PbQZ6ds/wzc1NX50ONycm
         zwQ5ocfNcA3KphG7+Mzxtv9Ygs97nclPtAODloQWpX/kWXhJJEFzglx+ezvduvWrFgEW
         1goWFvLdol42eHX+Nrcj/QnrHlBlcgluDZhtQRd73F9fRWWWplBQphTJU9ZwrMgboje9
         Tg6tuKD5l1CevI9gh0M/ciOkROjNns4PuFP9NYcToZ+8dsWz+MEhPqtVbiHxlXr0vNwO
         /UtA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112 header.b=pIbr7eUQ;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
Received: from mail-pj1-x102c.google.com (mail-pj1-x102c.google.com. [2607:f8b0:4864:20::102c])
        by gmr-mx.google.com with ESMTPS id u6-20020a05620a454600b0069f96278236si830136qkp.0.2022.05.22.23.46.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 22 May 2022 23:46:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::102c as permitted sender) client-ip=2607:f8b0:4864:20::102c;
Received: by mail-pj1-x102c.google.com with SMTP id t11-20020a17090a6a0b00b001df6f318a8bso16613940pjj.4
        for <kasan-dev@googlegroups.com>; Sun, 22 May 2022 23:46:40 -0700 (PDT)
X-Received: by 2002:a17:902:b083:b0:161:e861:ebe3 with SMTP id p3-20020a170902b08300b00161e861ebe3mr17479939plr.7.1653288400112;
        Sun, 22 May 2022 23:46:40 -0700 (PDT)
Received: from localhost ([139.177.225.238])
        by smtp.gmail.com with ESMTPSA id u18-20020a17090341d200b0015f2b3bc97asm4296153ple.13.2022.05.22.23.46.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 22 May 2022 23:46:39 -0700 (PDT)
Date: Mon, 23 May 2022 14:46:36 +0800
From: Muchun Song <songmuchun@bytedance.com>
To: Kefeng Wang <wangkefeng.wang@huawei.com>
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH] mm: kfence: Use PAGE_ALIGNED helper
Message-ID: <YostzHXNIE3qcgQt@FVFYT0MHHV2J.usts.net>
References: <20220520021833.121405-1-wangkefeng.wang@huawei.com>
 <Yods867HAh5NH2kN@FVFYT0MHHV2J.usts.net>
 <20d731fd-f7f9-4c93-d851-01972dc04cb9@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20d731fd-f7f9-4c93-d851-01972dc04cb9@huawei.com>
X-Original-Sender: songmuchun@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112
 header.b=pIbr7eUQ;       spf=pass (google.com: domain of songmuchun@bytedance.com
 designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
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

On Mon, May 23, 2022 at 02:32:59PM +0800, Kefeng Wang wrote:
> 
> On 2022/5/20 18:26, Muchun Song wrote:
> > On Fri, May 20, 2022 at 10:18:33AM +0800, Kefeng Wang wrote:
> > > Use PAGE_ALIGNED macro instead of IS_ALIGNED and passing PAGE_SIZE.
> > > 
> > > Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
> > Acked-by: Muchun Song <songmuchun@bytedance.com>
> Thanks,
> > 
> > BTW, there is a similar case in page_fixed_fake_head(), woule you like to
> > improve that as well?
> 
> IS_ALIGNED is defined in include/linux/align.h, but PAGE_ALIGNED is in include/linux/mm.h,
> so better to keep unchanged in include/linux/page-flags.h.
>

Maybe we could move this macro to page-flags.h or align.h so that we could
reuse it?

Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YostzHXNIE3qcgQt%40FVFYT0MHHV2J.usts.net.
