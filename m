Return-Path: <kasan-dev+bncBDV2D5O34IDRBMMTXSDQMGQE5OZ4Y2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3e.google.com (mail-vs1-xe3e.google.com [IPv6:2607:f8b0:4864:20::e3e])
	by mail.lfdr.de (Postfix) with ESMTPS id C316C3C8833
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Jul 2021 17:58:42 +0200 (CEST)
Received: by mail-vs1-xe3e.google.com with SMTP id k67-20020a6724460000b029025ff03ce7c2sf1108360vsk.7
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Jul 2021 08:58:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626278321; cv=pass;
        d=google.com; s=arc-20160816;
        b=h2XuEsd6EwfPYdQKCH2Nrhc7aA0KvzABxie2c4LjpCYkwpCJMG2HeL5Zu/hfzB8Tl2
         Dw1RVTsuWUxSnKUFRCzeCw9Qh9f1NEtGlrwHK5O91PE2f/h96TWj1KV5GkqaH1NeEDiC
         pk+qvhB+4EZnT+IjTbHj6JtH5RT+8nVRZA5nrVYzd554s4gGy118nrkyXFFQxl3sDZoz
         hWryl5LcmkY7JlySpivfwHxjiQGuqEKHTB11V+SakuM2qgJfQXkMcgqJAyLmriZCSUuy
         mG/cDVrFtx58L7UtIAmnHnwmHCpzpmeNHU1BESVSKRiE1TzI4whTbPkmR+35FHMmSgIk
         6G2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=qUeyhvnuTLv8ugkEWv0RX1OfwNPC3Pws28LWcqffncE=;
        b=BtjCstJBhDVovr/TJ0wo33QA9FJg1oDB+5qowfVnbndLiQfQhU7rJp0b/CVjvMi6+s
         mSd38kfrLQfUKGTiRiKmcNqxNdm/E/pv4egqM8dieHr0appwlHUMvArBHHUr6qNSshui
         VcAdVs4estqZ0gCmT28lzwtqM+9A9L8LvQLq0XbFFSumZSGwuiY0Xs41Wzw+vhTsosQF
         R0w4Y7+BYMQ9+EQOQWj7zRvi2SATqyPZImfcR70gXw/aflQ3KfJZb8lToAFQuK7mQfPY
         62u+lWdGt9MsD01O2cBQyDRl/FjiRbD+Tg4ZB7ycd7YJPTX/mptjBWej4aq5yWYYkoLS
         vhmQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=f5AG1TID;
       spf=pass (google.com: best guess record for domain of rdunlap@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=rdunlap@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qUeyhvnuTLv8ugkEWv0RX1OfwNPC3Pws28LWcqffncE=;
        b=Z8NnCDTwu6BfTaTVNW8aKWJX8gO8WLiGRtcaQjdgPM4hdQvYINgR77ruK+sByj0Din
         Ee+TiN9H+kyundCfos0ktSQO9AlDs01p3OJqwnq5azZ3XVaUWXXA7lo9x6bGiyw+GqW5
         xtLmvRcNanMTSzAMxB92xvTZ6nbkzNiwSEwHIkdV+VrZSy1jktxtpskKNzxop00Fimcj
         g0BuRq5K87sssKzscbDSsP6mcXCGLCphA3gbkKxymDAvw7VBYLUnzk64vKyQtp//S/Zy
         YnFVMTcXd/l32dQyri2pWXuC3V3cFurcnzcTBEYYy+pxBMg8rRpQi1hh8lyjHwcnCCB2
         2Qhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qUeyhvnuTLv8ugkEWv0RX1OfwNPC3Pws28LWcqffncE=;
        b=SBgexsSCZ7VxjyHLP1Jr9b1SW+fmdLRcM2LuHUdkt7nbp3Jt59jc6aLlIovLh1OWV1
         RZRyAYP9YfmUUAOil4rhhMtDwdNvC0nCQ4QyQz/i49z59p4DPI7bOoKYvRijDB7WkLRp
         bhe9DEFI4acbsRehU91hgxD/8faTPrLfo2yuJoweUZtS6Pu+O/z3c8zqfkXQtif/B30j
         BZSnYMLlPgRKWp76h3ZXkgn2dO61A2pX5llJtZc1TAvRXDfnG8bICQbT6GBtHJJG18gy
         yyAJMcpnScc1QxYuVWHJcn+s3dOfva6IlWKeaC9GWT9Y/Gw4/fdIgQTK8r6kFHbbySsp
         qM2Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533bngIfhm/0MQ5q7/3WaROPDoMRd6WfdzHFz8dYX6omCFk0i34s
	TtufAXP7S9WRgXbu4fidUmM=
X-Google-Smtp-Source: ABdhPJwZtBr5o/LbccKVdJhFOgaeH0L8Artf7Rqyla9L85ydRGpWgUiAaCeN75qWUXbaLcpAjcyzBw==
X-Received: by 2002:a05:6102:9d5:: with SMTP id g21mr14656437vsi.34.1626278321777;
        Wed, 14 Jul 2021 08:58:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c488:: with SMTP id d8ls935452vsk.7.gmail; Wed, 14 Jul
 2021 08:58:41 -0700 (PDT)
X-Received: by 2002:a05:6102:3a07:: with SMTP id b7mr14691138vsu.23.1626278321255;
        Wed, 14 Jul 2021 08:58:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626278321; cv=none;
        d=google.com; s=arc-20160816;
        b=fqVdb35f/S+m07CphbzZVZ6sJU/mV846OYRpPt2FFeofQn7bbw2MtASIMGtpCzLPkC
         IvIAg4hlf0PFKZConN7uEy5F0WCokLj+Az/VzuiH6cWUwlphbjzxikiojhNBio4lBK23
         OKwvSFIIbfT0qf5Vf/V+e+guDrujkjWBLve+bJ0OmspiC0TEiBSsUvQ4z4546Xji14Pu
         XbWiiF699nkIdXBtE2k1ShN0mCE3KfoxkwsfMcCkYM7ASb/pZPI1v4wCNkcw8JfaGx1j
         nUY5h+4iOqjV3fvzUSRtGVW9Ipx0z9373idozbVQJZNji5Q8i/rV9xgXA7eRuNA9wIf2
         8ilQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=Y1Jp3Hl9M92Nuxfx1/QPNtiZMokbdLy8C2g312gTFpE=;
        b=vKRiOPwViSWQyBZDjWp7xsMoXf5m9OXTspvLc6swF1H+DdJTrh0/DB2kRrLBu9LnYe
         I1bZGGAHC9e34iMTHkECwk9cT/CRN6Tn3a/LOIzs4NN4mXYNzOMltFrclnwiW4yEpoOS
         ScQRiAbfHtamiFOkDai7998K7c0AZS+nwX60clJFjDyuARkKwp5pFFt0UGIDU7w6FJr8
         fwWgqfCP8tBCztxoFk4iBbUvrU/w2FF2goSWLzNl7ryTqQyIG5iAqEX9IiHHPCT51GcU
         Kdkv15FLMTJh4GwXJ14yeK0TNE6W6FIaT04rqd/SAwhV9L9Xvfl8exyqjOOLF0wgw4rh
         ybOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=f5AG1TID;
       spf=pass (google.com: best guess record for domain of rdunlap@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=rdunlap@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id l6si331454vkg.0.2021.07.14.08.58.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Jul 2021 08:58:41 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of rdunlap@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from [2601:1c0:6280:3f0::aefb]
	by bombadil.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1m3hHT-00E1XK-3X; Wed, 14 Jul 2021 15:58:39 +0000
Subject: Re: Build regressions/improvements in v5.14-rc1
To: Geert Uytterhoeven <geert@linux-m68k.org>,
 Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Cc: Marco Elver <elver@google.com>,
 Steen Hegelund <Steen.Hegelund@microchip.com>,
 linux-um <linux-um@lists.infradead.org>, scsi <linux-scsi@vger.kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>, netdev <netdev@vger.kernel.org>
References: <20210714143239.2529044-1-geert@linux-m68k.org>
 <CAMuHMdWv8-6fBDLb8cFvvLxsb7RkEVkLNUBeCm-9yN9_iJkg-g@mail.gmail.com>
From: Randy Dunlap <rdunlap@infradead.org>
Message-ID: <b85a17e0-5e64-b48f-ceab-7cec19059780@infradead.org>
Date: Wed, 14 Jul 2021 08:58:36 -0700
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.11.0
MIME-Version: 1.0
In-Reply-To: <CAMuHMdWv8-6fBDLb8cFvvLxsb7RkEVkLNUBeCm-9yN9_iJkg-g@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: rdunlap@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b=f5AG1TID;
       spf=pass (google.com: best guess record for domain of
 rdunlap@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=rdunlap@infradead.org
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

On 7/14/21 7:44 AM, Geert Uytterhoeven wrote:

> 
>   + /kisskb/src/drivers/scsi/arm/fas216.c: error: 'GOOD' undeclared
> (first use in this function):  => 2013:47

https://lore.kernel.org/linux-scsi/20210711033623.11267-1-bvanassche@acm.org/


-- 
~Randy

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b85a17e0-5e64-b48f-ceab-7cec19059780%40infradead.org.
