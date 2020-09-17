Return-Path: <kasan-dev+bncBCC4R4GWXQHBBSG4RT5QKGQEII3VHTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id E162426D7CF
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 11:37:13 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id y26sf1031685pga.22
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 02:37:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600335432; cv=pass;
        d=google.com; s=arc-20160816;
        b=H3G4S2lLKSYPpk6kDVTFz+nnIw947gnvjuCjJ2bTpFfxapH4ilwI/riaaznNRU5Hfw
         KbrPUdOVxn0BF08OMTSFqw8k5QroXZvvnk/bDhtF89FKMCNiOb/9tWYc+abxyUeq8K4r
         JJkchvo094A3ar6zc6VGEAg0lr0FLvPzHKNk0X+Xic963LjCx/SNRRRdVrTtZ1nMuUm9
         yw9uyigFIfPUfaOKcb/BXaugK2yufUM00y+cYCHF0simGQKSHi88pzoPpasqlOP0J6Hz
         T4c0IHgzj/wIwQ+KHCA+hJh8FsjXOsRco+82jE4VGv8dX/DwKZavpVuCn9kITTFFVFYs
         zZeA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :message-id:in-reply-to:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Ky9iydHEMnXqDI/KscE6vUC/zP179o8ASWTA79UwXBE=;
        b=g2Ssvev0WMsLwORfg20RU1EIG3rgRJE1S31xpZ4TGt2VlbdOUJpAb3p9S8husf4W1c
         d9wfINGW2UIytfzzuPz7DswHMJSH7JsfZmc8Jp2ctoHEug5oen0il+sLSb0rSYcHQz7g
         ewa9P5295BD5NvST1O34xowffNNTWI23KVhCjOCQbccQcv9ZuzCago7AUznVAXdfwS70
         47DvrbHCdoUQHzOxn0ax6WfhpNUGnyhZGREd3O4Zt0m2LsD9DxlkysqP1AqIHHX18dWy
         rUSIRCumq43iM/iTBHMxsDzQkzIJNQ2kNI0bxSnTM1gtLB5VCey8t4RBdC/ZDdCwx4lQ
         gS5Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=softfail (google.com: domain of transitioning cl@linux.com does not designate 3.19.106.255 as permitted sender) smtp.mailfrom=cl@linux.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:in-reply-to:message-id:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Ky9iydHEMnXqDI/KscE6vUC/zP179o8ASWTA79UwXBE=;
        b=DVkk+xj5G5MX9qB6pSw/LAR/FckYP56Ra7HGC0Zv+29kpZsFfFMLFOD0kgIU/ATP6f
         nMhf/Acleofkl7+zDxokYgFRXd9Ab7NsnJrC/5oFKwOI4n5r/8w5IJFVESVR+PNom/dY
         sCghP1sLJbsMj99+ymzfwMu4lo4Ef1p0kMXixu3CbKbJ9CLq8c3hdWhZ4AKaCpWgPm6J
         C2Q6oSj/ySzga0M6spDghjYvFJxMbynPylDYUWYcpHXYnpinAeWWF8ySMobPdfvWNqpl
         3+XZ6SFMIiMRE2b5opjPMDs/R46mXbTocu4rkFDpWpdo26G6/A2LJjN3OebbyWiHdWkX
         Prtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:in-reply-to
         :message-id:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ky9iydHEMnXqDI/KscE6vUC/zP179o8ASWTA79UwXBE=;
        b=KfjY5MImidx7FF7BdH0RBYLECakI8mrGGJM9LFYSe4b4gIhWSSkysh4bpvRjWT45NT
         78V+0Z2gsKaYUxN4kChY24ZMZ4YU8HsPopJPhIO3lSRGjb0aAO/JF/qNgP0G1jt5za0U
         BcINew4EDXO2EdRC0y0/bGxA4tS26XvtTJb55T6g14aiEpkR4qVsl2ddhP+XCoZj8p5K
         UM2aR00Js2FgTRG4FaxuBGj/HrWiSlfehJXM6NaSQi29ZVwKMyvu5NlRoPuBix8f7vQk
         uyeQu/yZYXmiePUIP/IgrVQn1rYQOiR7tHZtWDAIImtNdHWs8Kzushgzp4UYE2+m59zi
         Q7lQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531V+OMx+ASg+CY67jaHYL1+qX8f1OdSsfV/zTIkSmA+j3dmRpte
	y7n+ELs7gUPCU2ZO8hXH3ms=
X-Google-Smtp-Source: ABdhPJzEyHOmC1kvlyZXbfNl/c+36oTKLzv52AWoE9bjnLYRvE8mEJmvTP6teuKoW75APwp380raGw==
X-Received: by 2002:a62:7c82:0:b029:13c:1611:66b9 with SMTP id x124-20020a627c820000b029013c161166b9mr25526353pfc.4.1600335432507;
        Thu, 17 Sep 2020 02:37:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:5ec1:: with SMTP id s184ls657125pgb.7.gmail; Thu, 17 Sep
 2020 02:37:12 -0700 (PDT)
X-Received: by 2002:aa7:9182:0:b029:142:2501:3977 with SMTP id x2-20020aa791820000b029014225013977mr10291316pfa.60.1600335431953;
        Thu, 17 Sep 2020 02:37:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600335431; cv=none;
        d=google.com; s=arc-20160816;
        b=cT2wgOqcJEgR2PDfsJpRZEWWWVYolun0KwD8fn2N4uj1RUBaY2k4s2U3lxnVcSxjm5
         PdrIEFQKdEw37qul9whv0UWghniKoxoOPdGZXhyrwI4FoNI7AQnFYIXWmTIee2G1KY95
         1YGolUCJbrPnJpVgBckESh9kkAoOJGwgsbbrB+k3XeOxjZWYtGK7SI1C6aNGveClS7Mj
         WSajCQTXpaA+QdtV2S3OMWzKZ09CalQjuwcnYZfmQY/YfyvyPsSrNf9sCJfGnbc2BL2C
         sMh5wf/mGebUVXyO+Lwu4wL0D3P94jTNMv5VB8hMYWxp9PpOh9QMj48LjsgliUsiG1NL
         rofg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:references:message-id:in-reply-to:subject
         :cc:to:from:date;
        bh=wVw58GB4kP9bJMR2G+tFFfXVEJ3vPODo3GS7ZevBosk=;
        b=kOGgiLd9fUXhPiCdpS9pwVqS4VGXJOuwY/8s+jPRghVN1GEsBwBnl90fbRwSCy3Paq
         HYgKpl6UeTP3IKcsN/ZRifMgVhhpBOBMzaR+1CKkfpcj+FJjafq8EM1tVzwOTPKLBkgo
         3qLq76cfVfEy2RddiCh5e49j+zqwJcmUuNB7uwVFZZAu27Qf52uOZfXCWkZ1FLCpVeeL
         VfUbr6FXG3Uk6EEowtNuP+l/P19qzu1I6oHIdYa/kbqw6eeALww9FRq/0Tkb/NBYwmg0
         K8gmpaiChbk0hg6yfKuJEu21D8il33WGGJis6ew7HmnEMNec6hvlduXz+rRI3JP5Vwj2
         Z85g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=softfail (google.com: domain of transitioning cl@linux.com does not designate 3.19.106.255 as permitted sender) smtp.mailfrom=cl@linux.com
Received: from gentwo.org (gentwo.org. [3.19.106.255])
        by gmr-mx.google.com with ESMTPS id v62si1137606pgv.0.2020.09.17.02.37.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Sep 2020 02:37:11 -0700 (PDT)
Received-SPF: softfail (google.com: domain of transitioning cl@linux.com does not designate 3.19.106.255 as permitted sender) client-ip=3.19.106.255;
Received: by gentwo.org (Postfix, from userid 1002)
	id DED1F3F0AC; Thu, 17 Sep 2020 09:37:10 +0000 (UTC)
Received: from localhost (localhost [127.0.0.1])
	by gentwo.org (Postfix) with ESMTP id DBB563F0AB;
	Thu, 17 Sep 2020 09:37:10 +0000 (UTC)
Date: Thu, 17 Sep 2020 09:37:10 +0000 (UTC)
From: Christopher Lameter <cl@linux.com>
X-X-Sender: cl@www.lameter.com
To: Marco Elver <elver@google.com>
cc: akpm@linux-foundation.org, glider@google.com, hpa@zytor.com, 
    paulmck@kernel.org, andreyknvl@google.com, aryabinin@virtuozzo.com, 
    luto@kernel.org, bp@alien8.de, catalin.marinas@arm.com, 
    dave.hansen@linux.intel.com, rientjes@google.com, dvyukov@google.com, 
    edumazet@google.com, gregkh@linuxfoundation.org, mingo@redhat.com, 
    jannh@google.com, Jonathan.Cameron@huawei.com, corbet@lwn.net, 
    iamjoonsoo.kim@lge.com, keescook@chromium.org, mark.rutland@arm.com, 
    penberg@kernel.org, peterz@infradead.org, cai@lca.pw, tglx@linutronix.de, 
    vbabka@suse.cz, will@kernel.org, x86@kernel.org, linux-doc@vger.kernel.org, 
    linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
    linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org
Subject: Re: [PATCH v2 04/10] mm, kfence: insert KFENCE hooks for SLAB
In-Reply-To: <20200915132046.3332537-5-elver@google.com>
Message-ID: <alpine.DEB.2.22.394.2009170935020.1492@www.lameter.com>
References: <20200915132046.3332537-1-elver@google.com> <20200915132046.3332537-5-elver@google.com>
User-Agent: Alpine 2.22 (DEB 394 2020-01-19)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: cl@linux.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=softfail
 (google.com: domain of transitioning cl@linux.com does not designate
 3.19.106.255 as permitted sender) smtp.mailfrom=cl@linux.com
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



On Tue, 15 Sep 2020, Marco Elver wrote:

> @@ -3206,7 +3207,7 @@ static void *____cache_alloc_node(struct kmem_cache *cachep, gfp_t flags,
>  }
>
>  static __always_inline void *
> -slab_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid,
> +slab_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid, size_t orig_size,
>  		   unsigned long caller)
>  {

The size of the object is available via a field in kmem_cache. And a
pointer to the current kmem_cache is already passed to the function. Why
is there a need to add an additional parameter?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/alpine.DEB.2.22.394.2009170935020.1492%40www.lameter.com.
