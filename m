Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXUOY2QAMGQEQ3RIVPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 814096BAB2E
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Mar 2023 09:52:48 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id d23-20020a193857000000b004d5a68b0f94sf5502833lfj.14
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Mar 2023 01:52:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678870366; cv=pass;
        d=google.com; s=arc-20160816;
        b=KyEd50L+3I62eTI7LqPUPvLd0dx7Z7HUnES8yNbWsfsVHm9d/49rXcyLGjPFprhVgc
         DufINEJ29dwfQAohjWj22q5ETDN/VHX6ClRPygAVcla7p4jezeClKL1HT2RU6mYMzDuz
         ZTkhBMf/R1689gs41tRboLJ3T25jJJ0mVU8L/h2hLVeNRj1Ig9yYb/bJpWTCiZatRMuK
         99vI+kYscODOA58RsyMOt++eRMNIEJYRPx/YzFoY6l+MFzIAw5rlQ/pyRGeSL8H8fptm
         mV3bkkaw45dlPHhhTPwzjHGBJLo3bQoL6fC4RXhiizs1EKFed8X4wv+tg9ErTSDhLq7I
         WQgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=MuT9+JZL5hOJQ0fhr17PeCB8ZP3nZbfEBIJun+qcQ0U=;
        b=HIh2Ji+leEDjEeLdUmYJDZUEVhS9Gmfv7Mku6rdXYSeu8MH7XHpCIS8O6vIxh2upAi
         uwpNCX8sgLIuyn5gwWYEu75bY5uocLVXy5A7svAxZhByl4xGHHdhEVI6ERS/gdneLxJx
         rOLfFc7ncyUUHfjkXTjNTGMbU/6aT7SAgwEm9f40tJ0yJOFWDrr9MZyodXZsq5LwYZPH
         7s1AY1IK3aOrTzmWamT8n/Il1yxxDmhg2ofYv09JsyQaiGbfDX54dSwWTPTJORhjqnY4
         LehVsqfUIzsG+KMFLk0FXf7DshztD4e8tlL+9RfNP7vHcTmtaKPgWxJAVj00VX6nQOkd
         u+pw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BQIPymLA;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678870366;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=MuT9+JZL5hOJQ0fhr17PeCB8ZP3nZbfEBIJun+qcQ0U=;
        b=Hxr8ObIINywX5Eg5kmVTIKrVO6KisjlVcQ+fsiXbTQ2mqBrXeB2rP4KLxo0yivvb3z
         vnlpvLUdUPl0Mug6apQWHBOom3nuIO2cDyO4GpOwsn6cKfaBCQtdE2Sx0TQ+OyIxu36x
         l+aWaRr2Lua7x7xWmrZwFBQp6IKfJiLsoHGvBP2S1e1YyVFr7JYX7oUgO60OxXAwhAxl
         E69ZALWf64wIqT6ezawdTLShhnQglO9T3ZHKJpjo4UEjrVLttASukESE3jJNQUQ2My90
         W6Ub8pfKk6hmi/PWJhRpEM+GXTxVEUknjLiXwig9EWZZXnieLxulf8yhaAoDrGA09JdW
         nyWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678870366;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MuT9+JZL5hOJQ0fhr17PeCB8ZP3nZbfEBIJun+qcQ0U=;
        b=EnuGnnH8KNNWCFDMXPnm13P9eKnFLoQRtzzMr4yuqKZs+hZaE+JtimdRlJImhWS8dU
         zXHr34cSUioRehzhF5GiIszwWYKgDUdBBRdIWehtnbOcgQxNfn3StvXW7oJwEi6yjsBV
         JjxNiPduHbQi3FdyjbL6DnYSvPVOECmphDWrz/hJeunpm7dgvl2fDL7tz0zRWSwCITvu
         nR6iATe4zTtOtotG2XmNNPfL2j8KxXfSD+YNkkDL3a+5KwQGCbbT1nR5DYO4aiSLPLDN
         QKRizAL92n/boB78jbPBljnaQErXxqv4wkgwNQTRjkRho0y3+PJ+fU6SCrruW0nfftsN
         YKxQ==
X-Gm-Message-State: AO0yUKXVQps6/mZE9mUJnxIweoq7mtlTUo95Jdiyjduxc1J9fhCL2C98
	Oja6t4BLllu/iQWWqR/Xtbc=
X-Google-Smtp-Source: AK7set8Mzd6qjmx65+jXtqgCO2pZMiRXaQB7l9ocKixjy9rKf/cnDQA6Wy67DYcUQErWBLH7NfBOXw==
X-Received: by 2002:a2e:aa27:0:b0:298:8770:548c with SMTP id bf39-20020a2eaa27000000b002988770548cmr614025ljb.8.1678870366343;
        Wed, 15 Mar 2023 01:52:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:15a7:b0:4e8:5851:74e4 with SMTP id
 bp39-20020a05651215a700b004e8585174e4ls1652295lfb.1.-pod-prod-gmail; Wed, 15
 Mar 2023 01:52:44 -0700 (PDT)
X-Received: by 2002:a05:6512:11f2:b0:4e8:20f6:83f4 with SMTP id p18-20020a05651211f200b004e820f683f4mr1588120lfs.21.1678870364623;
        Wed, 15 Mar 2023 01:52:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678870364; cv=none;
        d=google.com; s=arc-20160816;
        b=F/F42dNlb7AlJ4sLKR9zXmYXaLebERl+lt+IQMbInhUsaGddyicZVjyuvIxaQnYTiG
         zuVmRt/P5pT50zBjVkm8uypqBv0AZX2O9L5BXYMmIppg/6uPT4kHFF/jjEg/4Bqpbe37
         Gn+DcphM8K4Cnb8qu5nE5YAH3U7p/reBDVbqk3y9ybKG4p5UwSW3s98zrSPMZUkQIjuy
         DHgWczThxCDIB1NpHE3EMjoEYHSbqKhMJCzBKFpBsu1Bxew7rXHhe5KJPOOMxmC940cC
         MCXf9l7E9XUP+HoBKI9Yv1F8Y39XhtH1cSeRa1c+L7K+tm31+U87Ij5recMgwwXB8X9e
         LCVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=ykAWNeQFRSXWiMQRkG7ruLQaPcfN8XGu9YKzk/Snc/Q=;
        b=TR6UJG1yI8DXDDhuFoZPsp8CtB1PqAovfvDekylPGo9I9SnWWVPFeaS+dPZogP2kjl
         9nQZqsmUv4UP5ohwecJN94UCsqVF0qgod0/ENqzGYGNg2W8fSVOmIdjKmRUcnuGE3T4d
         iQHmY3wg4KhdFLRzMqduMsktpL4Z8XHeV/8sqsiLmOk8WD6T2cmWjr5ifBwPqo+YVsjQ
         XJ7G001/5hSzqKHQjhx//I+gcVMScCE+SaNOPqDty/eILiME5C083rbBeO2WWYVU4N/o
         RJmKdrVqnAm9Z8AF564SLyK64/hCMbtpa0+9x+FMzaOzVEw7TV9hshK2N9yv4idjyuuX
         SCvA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BQIPymLA;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x334.google.com (mail-wm1-x334.google.com. [2a00:1450:4864:20::334])
        by gmr-mx.google.com with ESMTPS id g41-20020a0565123ba900b004e85e286f65si43636lfv.6.2023.03.15.01.52.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Mar 2023 01:52:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::334 as permitted sender) client-ip=2a00:1450:4864:20::334;
Received: by mail-wm1-x334.google.com with SMTP id j19-20020a05600c191300b003eb3e1eb0caso589165wmq.1
        for <kasan-dev@googlegroups.com>; Wed, 15 Mar 2023 01:52:44 -0700 (PDT)
X-Received: by 2002:a05:600c:cc6:b0:3ed:2949:9847 with SMTP id fk6-20020a05600c0cc600b003ed29499847mr7151983wmb.10.1678870363925;
        Wed, 15 Mar 2023 01:52:43 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:54ce:e7e7:a29b:ab5f])
        by smtp.gmail.com with ESMTPSA id y25-20020a1c4b19000000b003ed2a3eab71sm1113920wma.31.2023.03.15.01.52.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 15 Mar 2023 01:52:40 -0700 (PDT)
Date: Wed, 15 Mar 2023 09:52:33 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Zhenhua Huang <quic_zhenhuah@quicinc.com>
Cc: Pavan Kondeti <quic_pkondeti@quicinc.com>, catalin.marinas@arm.com,
	will@kernel.org, glider@google.com, dvyukov@google.com,
	akpm@linux-foundation.org, robin.murphy@arm.com,
	mark.rutland@arm.com, jianyong.wu@arm.com, james.morse@arm.com,
	wangkefeng.wang@huawei.com, linux-arm-kernel@lists.infradead.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	quic_guptap@quicinc.com, quic_tingweiz@quicinc.com,
	quic_charante@quicinc.com
Subject: Re: [PATCH v8] mm,kfence: decouple kfence from page granularity
 mapping judgement
Message-ID: <ZBGHUYJ2OY9Pz93U@elver.google.com>
References: <1678777502-6933-1-git-send-email-quic_zhenhuah@quicinc.com>
 <20230314083645.GA556474@hu-pkondeti-hyd.qualcomm.com>
 <b1273aad-c952-8c42-f869-22b6fd78c632@quicinc.com>
 <20230314111422.GB556474@hu-pkondeti-hyd.qualcomm.com>
 <3253f502-aa2e-f8c9-b5bd-8eb20e5f6c5e@quicinc.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <3253f502-aa2e-f8c9-b5bd-8eb20e5f6c5e@quicinc.com>
User-Agent: Mutt/2.2.9 (2022-11-12)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=BQIPymLA;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::334 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, Mar 15, 2023 at 02:51PM +0800, Zhenhua Huang wrote:
[...]
> > Is it possible to free this early allocated memory later in
> > mm_init()->kfence_alloc_pool()? if that is not possible, can we think of
> > adding early param for kfence?
> 
> If we freed that buffer, there may be no chance to get that page granularity
> mapped buffer again.. as all these allocation/free are through normal buddy
> allocator.
> 
> At this stage, seems only additional early param can work.. Marco previously
> wanted to reuse sample_interval but seems not doable now.
> 
> Hi Marco,
> 
> Sorry, Can we thought of the solution again? like
> ARM64:
> 1. intercepts early boot arg and gives early alloc memory to KFENCE
> 2. KFENCE to disable dynamic switch
> 3. disable page gran and save memory overhead
> The purpose is in the case of w/o boot arg, it's just same as now.. arch
> specific kfence buffer will not allocate. And w/ boot arg, we can get
> expected saving.

You can get kfence.sample_interval with early_param(). mm/kfence/core.c
should be left as is with a module param, so it can be set at runtime in
/sys/modules/kfence/parameters/.

However you can add this to the #ifdef CONFIG_KFENCE in arm64 code
you're adding:

  static bool kfence_early_init __initdata = !!CONFIG_KFENCE_SAMPLE_INTERVAL;
  static int __init parse_kfence_early_init(char *p) {
  	int val;

  	if (get_option(&p, &val))
  		kfence_early_init = !!val;
  	return 0;
  }
  early_param("kfence.sample_interval", parse_kfence_early_init);

Nothing is preventing us from parsing kfence.sample_interval twice
during boot. At this stage you don't need the actual sample_interval,
only if kfence.sample_interval was provided on the cmdline and is not 0.

That will avoid adding another new param.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZBGHUYJ2OY9Pz93U%40elver.google.com.
