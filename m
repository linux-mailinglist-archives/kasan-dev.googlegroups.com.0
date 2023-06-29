Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBPFQ62SAMGQEQHKUJ7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C19A7428A1
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Jun 2023 16:42:06 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-2b6b98ac356sf7055171fa.1
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Jun 2023 07:42:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1688049725; cv=pass;
        d=google.com; s=arc-20160816;
        b=VhcvTjlnSdEWcv3W4g0sR98RsKWJD0BbwwfjilmoJYwpY5eEZKnWe0GWPdRMS5K6AR
         NpOWKtc25rkD/lzj+RVzNqPi8aFyqiB6tiQj/mOcbH/95dJ6rlTf6BGI67ovs8cggr78
         0Vbe3O6/t5f7qAcXRV+nYAKL9bzoQbKV8ps37pnf5tXr9cpv2SI8WNQkv7zZVkb7/q48
         /aLICsUWuxC5g8qFAc/9R8jiX4pCS+w96p0UfkhxQhjt7VwPbE/9kInNdyI37P7GjUIs
         IfGYXugJQh/s7/P1T9rQT4kwCjXLtJfjQGAVntDqzdjee6z7I4Q1MEi6FF6J1l+1oXz6
         nm+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=pfSyDA/AmSGtxrHDJEKC5MnO1jYKZ68KJipumCbvKKQ=;
        b=VPhp9EgIz+PFXpn6znbdvoZjVD006Ao9ompVRozsYYV33LmXZdPy4EW1ouM6Mxj/40
         PVu9RQuwwDT+oKEcwYqOMeKZs+XIyHwDwNtcajF4PsBPIlfXxFJQ3Ahuef0ZMH2htY3x
         NnowYrzqZz/0gIcajL5OCm59NdANevH5x3APeuLv3Ce4WddkADroCZdB1irkUBu94lI4
         uajnaSOERReWdndXoE6HgWs6YOqWOkTD3sAEw642lehgBjeAl5y25f56mSYy/XoSQQNm
         csNJPawGvTtQrl6vFxA1+rn8TejWytM8yGAxu5DFUbfzNGpDg794QhuKxHXU9VPhem4G
         a9hQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Zm83snf8;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1688049725; x=1690641725;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:organization:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=pfSyDA/AmSGtxrHDJEKC5MnO1jYKZ68KJipumCbvKKQ=;
        b=oKkLG5xLY+GEw5yFrqdGRxWD3cDhJxo9OhiSHNZ6gsGB+QwgBuGQc32HGMBZy4pEtx
         e47YMR3TDdMyY9tf11a/DSwh14C0Ufxeu36FXkIaBtBDoweWFyeHZO2972SgWyDmgPk5
         TX0xzEBJq0+gkwFhB9PkAe+OhEWrM3WhdbbiPmo1zUBdKtTqBZufsi5nQAtX8Wiu1eUi
         CaIystVS4FCNoSXBOCCxJ6DSKxRtMIRRR8COwkFLJumc7+HhXYHzDMyy/jYjqEJhA3o5
         VaIfbEzVl5B2w3IlV8FQaZLUgHf9zzhiB7oL3ucqk6gC85LkhRtwWGA/L/AITQ0ahEh9
         MAiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1688049725; x=1690641725;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:organization
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=pfSyDA/AmSGtxrHDJEKC5MnO1jYKZ68KJipumCbvKKQ=;
        b=bIAXJUKbnB6xgBs8rVj2g30ukI47NEl+qZou8J6GWQTU1THkLzoqNsysP6hdoV9mHf
         dsfSjedyeSqJlotyzLc1qn3cGDqzLBOi8hYNpXarHOgGD5co/jFNPWgz3mJbzAYGPTnr
         rxNLe/rXMx84vhYOwiVLm4hxSyQoXNjZQkNQvRVLavC+jK1ZqWYV/CCI8MoHD78OONM5
         +LaKSoEpCkaustyUlFQRH4yXctXsYqdl4O74o/UZiPtKWbK6ftTC7jbUo7mJ4LI15TPT
         UV/urT/FSytcLkxwnj487ElWnxWJ5bGvmrkjkjGa2K8Qwua3XhH5iHBLL2Eaw53qclN5
         0yhA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDzYzhECaZ4yzl1psbE0rF8kt/U12xNPpSALLovSDHt7wkyC+Jbt
	4p92yn/Oc7+muYFs7VupbWo=
X-Google-Smtp-Source: ACHHUZ7zkPQeu70xfgxPLVySDzMF4T27mUnWOLMbMt/rf/DaTs9T4BsX3gGSSntxU86BRcT3fP41ww==
X-Received: by 2002:a2e:8559:0:b0:2b6:9fdf:d8f4 with SMTP id u25-20020a2e8559000000b002b69fdfd8f4mr8201951ljj.29.1688049724654;
        Thu, 29 Jun 2023 07:42:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a787:0:b0:2ac:81ce:1bc1 with SMTP id c7-20020a2ea787000000b002ac81ce1bc1ls563301ljf.0.-pod-prod-04-eu;
 Thu, 29 Jun 2023 07:42:03 -0700 (PDT)
X-Received: by 2002:a2e:9943:0:b0:2b6:9909:79b6 with SMTP id r3-20020a2e9943000000b002b6990979b6mr9034785ljj.40.1688049723289;
        Thu, 29 Jun 2023 07:42:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1688049723; cv=none;
        d=google.com; s=arc-20160816;
        b=rr7Zdxm6AxpEMypQ62EmVxUADQV49Jg1mNhC16i8Wd5Hko5vf7iQ2dJKymrqe4AMJZ
         qECojy1+glw25QskYPamhisMamBdoqhM2+2AHo19x1l1g0LULSp/jHfEXYtGwbLPwiwq
         8WjNsusFkbf3Of611pV5O7boTMAgJez2aUxaQ5Uw9hJ+cjqGEvyAzMU4cuIbdbB2B2nh
         eroh0G+h6g7CSyvjA1r4F3zZUJSs4l73SrIn0H/ys74om6hcybD766yrex8DmROz2iQ8
         cJg2M3adoRGHdu7S49A32ruaLHp/XtvCCJ/1rSdcl141b8Mqh97dmolGimmEpremHX+J
         iQeA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=organization:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=/E/nHU4CpzLOREHy0Tb/APQ2Q+vrubq7sRTQS2maAHg=;
        fh=CjsA875SY5TlkRouQqjZxgQbTioRBkM0JgJpWGD9ry0=;
        b=APeBiwzUk3E4gmbdFROfrSmLksIhEFmry1zUIGLtvCcJREVWD2XBkWPcGVS4u2VGaH
         /WdoyhL1V951st91fvYyT8ma70RoIb8BpbUN4d2wtVsfW1sbcvSCkKc/GiRF7eC8x6bR
         Pud3EO4ClCRXQnlfaslcAjtW2e0vC4M1CA/FvLhHLLQDnupX6rlymLS24HcI2Ae1Zp9/
         /IvASYyNaQ64lUs5qwOHl2/hDzWULCCuF36ZuE0hBWnu0wbdHZ1eW0q5mafShEjrHU6G
         CcS9vXTTZe2CDeANluye7F892Z0B4mvs44/yPLZsszoOiwxo78rnKIAvy1BKc7+atOGq
         tZBg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Zm83snf8;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga14.intel.com (mga14.intel.com. [192.55.52.115])
        by gmr-mx.google.com with ESMTPS id k4-20020a05651c0a0400b002b481b84f4bsi677782ljq.7.2023.06.29.07.42.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 29 Jun 2023 07:42:03 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=192.55.52.115;
X-IronPort-AV: E=McAfee;i="6600,9927,10756"; a="362161231"
X-IronPort-AV: E=Sophos;i="6.01,168,1684825200"; 
   d="scan'208";a="362161231"
Received: from orsmga004.jf.intel.com ([10.7.209.38])
  by fmsmga103.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 29 Jun 2023 07:42:00 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10756"; a="841465734"
X-IronPort-AV: E=Sophos;i="6.01,168,1684825200"; 
   d="scan'208";a="841465734"
Received: from smile.fi.intel.com ([10.237.72.54])
  by orsmga004.jf.intel.com with ESMTP; 29 Jun 2023 07:41:57 -0700
Received: from andy by smile.fi.intel.com with local (Exim 4.96)
	(envelope-from <andriy.shevchenko@linux.intel.com>)
	id 1qEsqJ-000sht-0n;
	Thu, 29 Jun 2023 17:41:55 +0300
Date: Thu, 29 Jun 2023 17:41:55 +0300
From: 'Andy Shevchenko' <andriy.shevchenko@linux.intel.com>
To: David Laight <David.Laight@aculab.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>
Subject: Re: [PATCH v1 1/1] kasan: Replace strreplace() with strchrnul()
Message-ID: <ZJ2YM96/jTi6E4Rk@smile.fi.intel.com>
References: <20230628153342.53406-1-andriy.shevchenko@linux.intel.com>
 <6b241f45a61f40fe9b221696289fd658@AcuMS.aculab.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <6b241f45a61f40fe9b221696289fd658@AcuMS.aculab.com>
Organization: Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=Zm83snf8;       spf=none
 (google.com: linux.intel.com does not designate permitted sender hosts)
 smtp.mailfrom=andriy.shevchenko@linux.intel.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=intel.com
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

On Thu, Jun 29, 2023 at 02:32:13PM +0000, David Laight wrote:
> From: Andy Shevchenko
> > Sent: 28 June 2023 16:34

...

> >  		/* Strip line number; without filename it's not very helpful. */
> > -		strreplace(token, ':', '\0');
> > +		p[strchrnul(token, ':') - token] = '\0';
> 
> Isn't 'p' undefined here?

Yep, should be token. Not sure what I was thinking about...

-- 
With Best Regards,
Andy Shevchenko


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZJ2YM96/jTi6E4Rk%40smile.fi.intel.com.
