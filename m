Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBZ426WSAMGQEPD2YNVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 15C94742327
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Jun 2023 11:22:49 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-313e6020882sf196288f8f.1
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Jun 2023 02:22:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1688030568; cv=pass;
        d=google.com; s=arc-20160816;
        b=CYXlOa+vHVNmUf5aGFcQtPxgqy7WyPCLeEH7ScLFoj6KIyGsiIlXrS2LAVArKy6Pzr
         ibjEEsQdHLU2E5VDenqpfreCM1qZi6F/b8/5mEN/6USTYcVHdISJi+q2iZZrDn3dAMxr
         OwLCnr1bpkUvicE+yGQExOwImeGwHOkVCb3Lbv+XxGuqSedl2OxLYsj2C0DCFpLuftPb
         bD21ZywvPsU7RzZ8+2jOg6A+r+uq75ObkdPXtzDNBupVwDgpE038NEcG/lleD9sSY3Kw
         hmjLSHnxLT1B9u668NSuJg2FapqvxW32OTBPJ9Hi5gvRE0rfRT9Ob7sN0xjrk8VYJeuQ
         EMVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=nYynU6Pq9GVO4p1R1yqv9bXtS1i8125SC6mc3PDRtnM=;
        fh=oJEGvmqGpB6zxnhcCDaOyJbCeiNEoA/wKf5UBfI3crA=;
        b=gdvTF4+5Ne7i7hpW2V1q+4A4wf1QERQQwNowfvzTgpqwWmHl3eOTKaaUbji/XvpxG8
         ounUQmofDEmKS2MXZj3dAuFKwnzkQTGp8YuiW+EYnaCLOwxORIlMAYXBuUeOUZfHgxot
         V52msriOq1QmlUbx8fwA5sVPxqiBqBguLIcA/qaX03CVYcY4KBnzZ/sRIoDhs5wDnq57
         9VgLenrx2Cigx5F8do7M4rBG3gwpNPiOKBiX8D1SKkInGL/cL5/LUxtUb3XjL1svIALH
         LXnLHcYhqSwE0mKx1TH/kqSYNv/UXHl5M9igP/35OjNCFBOw+KgrHlhWu0orptSluCD5
         iL2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=M9YEfHpf;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1688030568; x=1690622568;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:organization:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=nYynU6Pq9GVO4p1R1yqv9bXtS1i8125SC6mc3PDRtnM=;
        b=Gg3Zjl1ybekrZrjv27twJZDajbUYOjjGMEpfgZZCAPgbPJnh57X8Vb+TqvKW6t1gJh
         y46rlUWn8bH/YDP8TsQUuxGjJ/JEYNx4b4oj0rvhxH+nXNaneLWGRLr5JjBwUlubqJOa
         zSbLGcKTpqnN1Z9Dyjo8isiI1SO21vNt+2pNb1UtYCFZlkECeX6CjG+NhHJFc32tceit
         NOwb4uWFiBZudtCeM4zRKzvsQSBdKYMhDYUEam1Z7SaND7nvwNAA6J5fQgpYszvmA275
         6qM8Cibr7mBwxO6SqBK6iHF2vrBdcEGamRQdFP4ugZKVH/stvltdggjEj4nKl9f3prFw
         Qg6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1688030568; x=1690622568;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:organization
         :in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nYynU6Pq9GVO4p1R1yqv9bXtS1i8125SC6mc3PDRtnM=;
        b=VrWWALXQ3cSaO17hLh6hh2XAeXqRrQqXKAbDDGisA4g0bTxk3Ox5SC+5yPCPgCIVPq
         JG1jm3+NGS62Aaiv8t18fCrc5ZJD1Tr2Ly1t0+TfVmiLyK5chUZZKcwHJdVzpC8zWeBt
         KAxkweBcl+YtXwaIcWxdmVLxKMDOJyHtyAsP8oP4ar6rrCNlFe6++BOLGZezbpi+aCqT
         uuWWiNBAqvsQiKOSyCawmc25ympJ5cDxWv2VT2p80ONgfGs8voX6CaDKP2ZS0OUkeITg
         dFLRRMMyLBAccsLzfF71cJ/rP8qdrtnJdvY8BDt90ksDeIqVEQLwtUsD6pC5IZFoAqfy
         8GGA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDwZtSB+lLJ5R1Ke6Mt79LDjBBtPUZbY9rovCL3LnjXiB9Dgamli
	HoKAU5248pp2SZsetILXMBU=
X-Google-Smtp-Source: ACHHUZ6+74vN1k2F8WufE2LTP0Xu42QwHt2dYzzhvZJXR/MK6q9F3So+JhFLKHPClcd2jGJFo/JXzA==
X-Received: by 2002:adf:eec7:0:b0:312:7d4d:f1c0 with SMTP id a7-20020adfeec7000000b003127d4df1c0mr4169263wrp.32.1688030568113;
        Thu, 29 Jun 2023 02:22:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b10:b0:3fb:422d:501d with SMTP id
 m16-20020a05600c3b1000b003fb422d501dls229401wms.2.-pod-prod-00-eu-canary;
 Thu, 29 Jun 2023 02:22:46 -0700 (PDT)
X-Received: by 2002:adf:ff8b:0:b0:314:c6b:b9a2 with SMTP id j11-20020adfff8b000000b003140c6bb9a2mr3669065wrr.13.1688030566851;
        Thu, 29 Jun 2023 02:22:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1688030566; cv=none;
        d=google.com; s=arc-20160816;
        b=QHWvKGfQ9UMsBLQ0KMJUGx+aIl4FaCNNgE+NdI0taiFjqKHXXShaAxtCau1UEI7zgP
         kIk2PlA2HKjW7nF4hvPKgWVlKGKHsGScrX1h5rrNJVB4QEH1ZWjOW3Y9AleJvl6uK5/3
         GMhICTBOnAQJfGxpV0uu8bU1YUcU+19utMjBZoWM4G1Hg6GI/QfHWfhqhqe9Flm52qnA
         7OV167UyMP7I5eOHOUDw5gzHMFOIP9ieuLVgSPPCsFjhJDJNBPDzskA1B68h3x2LQoDF
         GAskAnn/O7zS53pT5IbnuJ08t+jDvKGz0IXlyIuo2rlsktrccr/oaviBvhrewXl+6Rqo
         6MjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=organization:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=6VGwAQ4Mq2HZsq6DtsdkLPdNrBBoYj4oDRTrauv82qc=;
        fh=TEA+DifO6hoID0PaZSlQizRwIbnT5g6SSMS2rTyyKhU=;
        b=StQHos377e4oi6j8bJbimrQ7+XvzobdIVm/RWTfqJo/m316PC6+eUzvaeqLbPSa92F
         vfXEMmhpyYKamaMeRDofPlGkTy6UpzyuxPVi/SfESL6YP1EZEHy4Sm/7lkk+8ecuPK5E
         scjcP/22LWUxzSLuuJCuGBvwy8aZXuZ+okMD85mvKe0ZUbb/bphoPgPxcFPUnnrr8cUD
         eALL1QcdDt144/QRmhPqUx5VIilDbssunYJxOPXsZ3qjbYO6Gw0CPzf9DouzBf/7QjD4
         bybuVYRRI1CHWkCf5+key3Z+eFjdIam4cQxdVyU3J0Jq/sKSuIq6q51IXx+0cAEi1iRG
         p+Uw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=M9YEfHpf;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga04.intel.com (mga04.intel.com. [192.55.52.120])
        by gmr-mx.google.com with ESMTPS id ck7-20020a5d5e87000000b00311110bace1si780798wrb.8.2023.06.29.02.22.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 29 Jun 2023 02:22:46 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=192.55.52.120;
X-IronPort-AV: E=McAfee;i="6600,9927,10755"; a="360913465"
X-IronPort-AV: E=Sophos;i="6.01,168,1684825200"; 
   d="scan'208";a="360913465"
Received: from fmsmga008.fm.intel.com ([10.253.24.58])
  by fmsmga104.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 29 Jun 2023 02:22:44 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10755"; a="782622678"
X-IronPort-AV: E=Sophos;i="6.01,168,1684825200"; 
   d="scan'208";a="782622678"
Received: from smile.fi.intel.com ([10.237.72.54])
  by fmsmga008.fm.intel.com with ESMTP; 29 Jun 2023 02:22:42 -0700
Received: from andy by smile.fi.intel.com with local (Exim 4.96)
	(envelope-from <andriy.shevchenko@linux.intel.com>)
	id 1qEnrM-000oP0-1N;
	Thu, 29 Jun 2023 12:22:40 +0300
Date: Thu, 29 Jun 2023 12:22:40 +0300
From: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
To: Alexander Potapenko <glider@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>
Subject: Re: [PATCH v1 1/1] kasan: Replace strreplace() with strchrnul()
Message-ID: <ZJ1NYFtTJ/9CZ0qU@smile.fi.intel.com>
References: <20230628153342.53406-1-andriy.shevchenko@linux.intel.com>
 <CAG_fn=WjLDsnUPKFwF8XJiyqYP6M+Q9ZqUweRPzPT3dW0i_E+A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAG_fn=WjLDsnUPKFwF8XJiyqYP6M+Q9ZqUweRPzPT3dW0i_E+A@mail.gmail.com>
Organization: Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=M9YEfHpf;       spf=none
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

On Wed, Jun 28, 2023 at 05:39:26PM +0200, Alexander Potapenko wrote:
> On Wed, Jun 28, 2023 at 5:34=E2=80=AFPM Andy Shevchenko
> <andriy.shevchenko@linux.intel.com> wrote:

...

> >                 /* Strip line number; without filename it's not very he=
lpful. */
> > -               strreplace(token, ':', '\0');
> > +               p[strchrnul(token, ':') - token] =3D '\0';
>=20
> Why not just
>    *(strchrnul(token, ':')) =3D '\0';
> ?

I don't like Pythonish style in the C. But if you insist, I can update it.

--=20
With Best Regards,
Andy Shevchenko


--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZJ1NYFtTJ/9CZ0qU%40smile.fi.intel.com.
