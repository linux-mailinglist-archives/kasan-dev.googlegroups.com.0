Return-Path: <kasan-dev+bncBDK7LR5URMGRBLNBUO2QMGQEHOEFPQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 789589410AA
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 13:38:22 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id ffacd0b85a97d-3685a5a765fsf1954110f8f.1
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 04:38:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722339502; cv=pass;
        d=google.com; s=arc-20160816;
        b=vq7zyxjj7NicGemQuYWThczwi8vGMIz9Iohrcxa44InKpJbanA3CDX0+jyVGXDiOk8
         xsHqCjSoQPkqAgcXFY28RoRRFx6QOjt1FbnH3L5SH6eObnEBkqr2d7vT9ztrk0DGfdto
         Sy1C4cr7+NR/37IVf/8qCapgV23z9WDUnJVcJ08S9LQtxzMZXNNUlIsOzgNj4zDTL8PJ
         tcx7kZi25oms/jDcnIzTxC0vcEL13gTINHm1wu/wAmU542Ee0h7FyQ37dVPCJc+/VEuY
         eJgUESeYAV64saApboLXjCPFkLrkkuwqNLUr0ZAXk3AZxv3dMvsPgPM12nPkqaFruOM8
         NB8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:date:from:sender
         :dkim-signature:dkim-signature;
        bh=3awme9eYfmWhp6jfa6548t+wszXgdU8QT2GjIO1WoEk=;
        fh=qy6DoT00KvA2cdpRUEcoKbPG156Gh/sEHxGm6ymaQCw=;
        b=tMN4TjIVazL5kyEli+NTQ7q3oIJsYXleY6t+NA2p/P4w5HcMeVMcab1H7H0yeaO0b/
         iW+ybLd54Ey9mT1M9luySyDK/VPjZL4by7pH4dmsmwZkEK0KzgvPeooS7UTtxuYOqQPp
         2Y1kpK8n/VmhGCqSCOiELOogmrpXFKKZabCPwcjnPbQQPFgxL2Ps6l/F7fjEYOATj4hK
         FGv4cJa1Mo+u6brfhr+HyDhmSl3+JBsj2yXfrCpp4j23kN65IuXJxE5Z4E5H7cbtIVoI
         2l1uYvfbQVX3UPfeKv1B/lJk4nZrQsYY3OSbBn78YoBziDCBE7fCnLjvMb9MUlggUjHV
         DMtQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UWZkcWSn;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722339502; x=1722944302; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3awme9eYfmWhp6jfa6548t+wszXgdU8QT2GjIO1WoEk=;
        b=b9omn5IkW0SquuD5iERzDr+92VTEudXTQhw/FgE3dr8ZNZGoIVEh4ELQ+uE83vAHcX
         eY2vXPqcci7Pg4kREoqF4C1y7lSrBp1mjeuwPnlN1fXi5mptgQKaFWEcywTQ4EKbo/aI
         RiM1rzCgD1XTA8dNnv0651VvSUoOeLTOCiZcNNWNR+AJU8IuIGK1DCRhcm26UmEhTsqp
         5Ja752PsADrgdZgnAP0L+SL3smrBbxG0pTRuePktGYqyTqISv/vyiD5TMCH734ee9uL3
         TbW9yEIAxyoqkJyXGmhjNuaHtqYGu1FbL3YMHyZ/1bLePurbw1K7+KyQwYMt+7y8xRqo
         B5Dw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1722339502; x=1722944302; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=3awme9eYfmWhp6jfa6548t+wszXgdU8QT2GjIO1WoEk=;
        b=LowD88oKJM3Hx+KfSYSBCPmoXKa1dChnCPJEkeE6zFEb5WmkzdqtIKhAoAxbEz/HzT
         OtW4lE1Gl33BnKB6Kux4Bdi9B5THeKmyu5ixLmxNFGcU5WaV6rus1ckIa9G2043dlVh/
         PQENX147zOLA6t72++ZSU8AdcuWuDdXBKs2Jy4r8pUjtpBVrW+XA0DnSeZ/zTG5hyx2Q
         ZNi//Vj/jlJ1cjaEuXKARij5kfHFs8v83Gws5tZiiOPQmPPDposGUzOr3jfj0EHCZ1Jq
         fuRmeHzk+TONsjDRVrNL6z6ZTna1vFoHS3Hbn72kBwaYhJR3N/ADEn/CtVXTEjYMqIUG
         6H5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722339502; x=1722944302;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3awme9eYfmWhp6jfa6548t+wszXgdU8QT2GjIO1WoEk=;
        b=ejBZOl6nqrlU16Z1djkoDWmSKOOcPWsB668x2Fff9X2ydmUuf+xoy5ufWbdXFlrwjq
         p2Hq4L3qi3XeTQdxgJzdCN9OTCsJSan7NYlbC2TO211VHJjN9EXTKrboEJsBVXoarq0D
         sOtf16/dI6HPw5Sk7kWhhBq88I0TokHi2tJ3SA1ryN4vgRXUL77A2ot/5Z5uaQEa62nJ
         n2gujKTdySa0L/Kaurb2XDGcT0CbJgSxeqwUQcUu4IMJvhP62+W27uxqhTbX2qxec3yU
         /QON7RoNnM+H2CWz2hbteeRRhco3gx/tRbGMSHLFSKVmF+fyhvt007I0GTqikihQUuHe
         7vQw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUt+2uQc10JKbOcH3HqUSm0LVHBgs3mZSxON293EqSR8D7KFBRoYu/hyXxQvgrvl8LU22RbOvGWcugVPVDchh0EnITs5aRlBQ==
X-Gm-Message-State: AOJu0Yz3JM8SZwDgpORK3imfR47yL8FcVAFwYj6bDucB4EC7Sgi/U73+
	f2FY1lYwW0LZGe4qnyuMOFaphMIcFgV5dwqsQICqZBFt6xNvuvJx
X-Google-Smtp-Source: AGHT+IFxY0tBxuFR0rau/rz598UPq6pa2q1seSCZ+Gy1DQNuMPcDN4Gf6uciOMzsdtbR8JhkuU/fog==
X-Received: by 2002:a5d:4f10:0:b0:366:f041:935d with SMTP id ffacd0b85a97d-36b5d0bad66mr6408573f8f.60.1722339501360;
        Tue, 30 Jul 2024 04:38:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b05:b0:426:ab3f:fafb with SMTP id
 5b1f17b1804b1-42803b66092ls26909715e9.1.-pod-prod-04-eu; Tue, 30 Jul 2024
 04:38:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV2zV9Xf7KcXShi5JVF3j5aSQ6ZwckW9CYOhqBwioDL0ZicI8rK8Jn/fyIQfE5Ccgf5/NSVMqD6HKc1hloCsCQ4Ux0+D7Leb25Enw==
X-Received: by 2002:a05:600c:3ba5:b0:426:5d0d:a2c9 with SMTP id 5b1f17b1804b1-42811d89a50mr70288155e9.10.1722339499310;
        Tue, 30 Jul 2024 04:38:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722339499; cv=none;
        d=google.com; s=arc-20160816;
        b=N5aRVmd0nmtdvebeHq7YjSC5EedkNpVGCCwWENrrhUAmcNqFt3od2u/HKPH5suCsmP
         aaPzHdBRyWtT65zlwEp6snponrXaz1QS/nU6RUOHi1Re7kaG0c/2lP6iEwkFR2QIlGXZ
         yf2llte/YLaUvpGfTveEBHchvTnqChv6VN9kb5KoNuCI3dxJQoqM3H8kGNfGi69YJg5o
         DTPzAZSKqWUUJ/IQcf/G35XnjEkXGvAzuoziuyPrqejJVvmvYxQiB5+kWyGUJvgLuabY
         0yG6CvNBRXk3ljJRFs2icrFl+CXiXcB9ygKDab55jQD7TLGzhvUndMIlWedaqDv+ptf2
         Rxgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:date:from:dkim-signature;
        bh=lP9ZC3R5hMrSLBrjIcRWHj9UaDtclwyOij0udu20d1U=;
        fh=wSuTT3k6w4EJ2b8o0WGlvomVW6j8kGkt2EBcvCzprtw=;
        b=VcTrc0FQ2RFzTWRG17uveS5gaxPm97o8or4ChSWTqYAoBG436BSI2wZVnw1aVYd8ts
         V4lmdATf4NmrvSTEVQQ2kjWbDOW2J88USfp8NtR1VYR7ZOuIIGzbZZE5M4CH+4fi3yc2
         rcqgiSxie8dHPTDijuoZD7r4mCWAnMl7vQjuNOCXBZMk88d24IeqVV3g78mI2qzR3wfi
         O2aI+BVKUkxNGIGT5IRpGGz8jUnHm4G1BcMQN2mctP51tV0g4oDchSBjfRp6+s0RaBl8
         Qm+uOM1nPyQQ4qE7RKzl0Ypo/fzi3EhpnjNB9YCq6tdmaW/0vAyxOMJUcf4b1Jw7WdZT
         OuSw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UWZkcWSn;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x133.google.com (mail-lf1-x133.google.com. [2a00:1450:4864:20::133])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42824af684dsi887005e9.1.2024.07.30.04.38.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Jul 2024 04:38:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) client-ip=2a00:1450:4864:20::133;
Received: by mail-lf1-x133.google.com with SMTP id 2adb3069b0e04-52efa16aad9so6682640e87.0
        for <kasan-dev@googlegroups.com>; Tue, 30 Jul 2024 04:38:19 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW95Wr9LIeb0D2HuWkR8BI303cKn+R+Kajm9b4I54qLqavaAb2I+1RDUoCljUBu22FMjtrPjJA0mpt9II1J0bCFKTAOS/xmt6cU6A==
X-Received: by 2002:a19:7404:0:b0:52c:d80e:55a5 with SMTP id 2adb3069b0e04-5309b2c3071mr6147385e87.41.1722339498077;
        Tue, 30 Jul 2024 04:38:18 -0700 (PDT)
Received: from pc636 (host-90-235-1-92.mobileonline.telia.com. [90.235.1.92])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-52fd5c08ec2sm1876073e87.127.2024.07.30.04.38.16
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 30 Jul 2024 04:38:17 -0700 (PDT)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Tue, 30 Jul 2024 13:38:15 +0200
To: Adrian Huang <adrianhuang0701@gmail.com>
Cc: urezki@gmail.com, ahuang12@lenovo.com, akpm@linux-foundation.org,
	andreyknvl@gmail.com, bhe@redhat.com, dvyukov@google.com,
	glider@google.com, hch@infradead.org, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	ryabinin.a.a@gmail.com, sunjw10@lenovo.com,
	vincenzo.frascino@arm.com
Subject: Re: [PATCH 1/1] mm/vmalloc: Combine all TLB flush operations of
 KASAN shadow virtual address into one operation
Message-ID: <ZqjQp8NrTYM_ORN1@pc636>
References: <Zqd9AsI5tWH7AukU@pc636>
 <20240730093630.5603-1-ahuang12@lenovo.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240730093630.5603-1-ahuang12@lenovo.com>
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=UWZkcWSn;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::133 as
 permitted sender) smtp.mailfrom=urezki@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

> On Mon, Jul 29, 2024 at 7:29 PM Uladzislau Rezki <urezki@gmail.com> wrote:
> > It would be really good if Adrian could run the "compiling workload" on
> > his big system and post the statistics here.
> >
> > For example:
> >   a) v6.11-rc1 + KASAN.
> >   b) v6.11-rc1 + KASAN + patch.
> 
> Sure, please see the statistics below.
> 
> Test Result (based on 6.11-rc1)
> ===============================
> 
> 1. Profile purge_vmap_node()
> 
>    A. Command: trace-cmd record -p function_graph -l purge_vmap_node make -j $(nproc)
> 
>    B. Average execution time of purge_vmap_node():
> 
> 	no patch (us)		patched (us)	saved
> 	-------------		------------    -----
>       	 147885.02	 	  3692.51	 97%  
> 
>    C. Total execution time of purge_vmap_node():
> 
> 	no patch (us)		patched (us)	saved
> 	-------------		------------	-----
> 	  194173036		  5114138	 97%
> 
>    [ftrace log] Without patch: https://gist.github.com/AdrianHuang/a5bec861f67434e1024bbf43cea85959
>    [ftrace log] With patch: https://gist.github.com/AdrianHuang/a200215955ee377288377425dbaa04e3
> 
> 2. Use `time` utility to measure execution time
>  
>    A. Command: make clean && time make -j $(nproc)
> 
>    B. The following result is the average kernel execution time of five-time
>       measurements. ('sys' field of `time` output):
> 
> 	no patch (seconds)	patched (seconds)	saved
> 	------------------	----------------	-----
> 	    36932.904		   31403.478		 15%
> 
>    [`time` log] Without patch: https://gist.github.com/AdrianHuang/987b20fd0bd2bb616b3524aa6ee43112
>    [`time` log] With patch: https://gist.github.com/AdrianHuang/da2ea4e6aa0b4dcc207b4e40b202f694
>
I meant another statistics. As noted here https://lore.kernel.org/linux-mm/ZogS_04dP5LlRlXN@pc636/T/#m5d57f11d9f69aef5313f4efbe25415b3bae4c818
i came to conclusion that below place and lock:

<snip>
static void exit_notify(struct task_struct *tsk, int group_dead)
{
	bool autoreap;
	struct task_struct *p, *n;
	LIST_HEAD(dead);

	write_lock_irq(&tasklist_lock);
...
<snip>

keeps IRQs disabled, so it means that the purge_vmap_node() does the progress
but it can be slow.

CPU_1:
disables IRQs
trying to grab the tasklist_lock

CPU_2:
Sends an IPI to CPU_1
waits until the specified callback is executed on CPU_1

Since CPU_1 has disabled IRQs, serving an IPI and completion of callback
takes time until CPU_1 enables IRQs back.

Could you please post lock statistics for kernel compiling use case?
KASAN + patch is enough, IMO. This just to double check whether a
tasklist_lock is a problem or not.

Thanks!

--
Uladzislau Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZqjQp8NrTYM_ORN1%40pc636.
