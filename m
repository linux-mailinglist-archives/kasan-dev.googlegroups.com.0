Return-Path: <kasan-dev+bncBDH7RNXZVMORBCVS5GXAMGQESLJ2HTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id A633886279F
	for <lists+kasan-dev@lfdr.de>; Sat, 24 Feb 2024 22:01:00 +0100 (CET)
Received: by mail-pg1-x538.google.com with SMTP id 41be03b00d2f7-5dcab65d604sf1721515a12.3
        for <lists+kasan-dev@lfdr.de>; Sat, 24 Feb 2024 13:01:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708808459; cv=pass;
        d=google.com; s=arc-20160816;
        b=jnk1Vkfy8sLaRSKOgroV6nh1SBfnNgmO87aiPRN+DCFkUvTH0voZiaDk8ykrpEFdya
         9E5nT08qVJbloOeJF9oFrkqPke55RjMO9gis037sWU3aCfauEQ+eaJFeoLZQ0PrULnWV
         mPrUMVlCMTkJ2khR07WGCDmia3dnJIp6pYTEriVFoQ5BxDQ4PTQYbKMApXiRnxWZ2N2q
         Dqwey+4DWU03HkCz/zUI1C8xQBhIUZnlTxzKdkvUfV0Fvl/YvCksYqsgnS/20xe/u2th
         S17RcSDrqQGQNtu0bjmbaw19ZMyVO4qAoqwBgDnCE/0dCDBbFsM4gnT90obiQEe/ZqJB
         9cPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :message-id:in-reply-to:subject:cc:to:from:date:dkim-signature;
        bh=xnIJ6YNRgsb5V/f1ja2YBNpVnfmtuPjmHJm18TjMQQY=;
        fh=AK2ttpXI/4XqAi70WGprdJWaq7bmTTHy4QVe3p9iodU=;
        b=bO0qjzOA7whi/IfDHdJu9/wovcE5ungUUBxoF9ty1eKsNqHB8ie02ftv0qRJcGegx+
         OUGMC+J7SHxHwAYYTF26ZKuMCiau/XrQ7gD2Hgk+wu0Q1MpSTnEGwWyqVd2RbzoJaK9i
         gKUnK288WxgyospxjjgNpQVrpxLTtT7ydd/57kZjOPdwo3lYuEVF+xKj066BvaZ12f2v
         cvfiswMRUp/gTqb38KIIue+WGJrW3HOzZLQiuyw2eddfhArGFfY/oxBnudIoFBjkbo0r
         XfP67nWoaX6bdn3EwkHUDiZSn94fVkcT3X4JzmZ7+Z2DULrVZZ33EPpeKMKYo5BU+Osm
         hSDA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1+bNYSqe;
       spf=pass (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=rientjes@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708808459; x=1709413259; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:message-id:in-reply-to:subject:cc:to:from:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=xnIJ6YNRgsb5V/f1ja2YBNpVnfmtuPjmHJm18TjMQQY=;
        b=eWnybZ1w3ZBISMllbYALu0h285sjn7fbP3lsTIBXCOo+5cKP+rGPau11EoMmfn6dYL
         Zv6hTOm66mZDc3Kp6PXvB36ErqZ5TfhpSwcX6Q+DlIwi+GvA5qIPK/VqAKhlDA4qXDzK
         PNxQdm1P03NPXkG66iXNups4jjjN7Oix3tP7LWioHLpJUQ7m89VwoJVPI+zYzB7b6ZW0
         w8H7zlsRjU/xTT70Kp2/PK6pt3Eh7/sI8vTVLu+v2bngi0BK84dbgzf0vPFb0Nl5Zu80
         xIPVMvfPENwHiTGYVDROEgbJUHO0iHRp9mbUN+3AFVWTnmHqXR0t3eTUg4rJX7U/jx4i
         AwYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708808459; x=1709413259;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:message-id:in-reply-to:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xnIJ6YNRgsb5V/f1ja2YBNpVnfmtuPjmHJm18TjMQQY=;
        b=hP1gQT/42k2BVomZkgdkNgtH+ZLZhFipSN8ExahiUir4SHdA6Mg7OqkgEPpXcc6Oxc
         iJmNJFP/yR4p8TO2QXHB7cxj7Krw3vGJb099Ers/SCJL8NMuLo2WVhDyZIuskpE4u63r
         kpN7w/Ed7euZd3b9vZ0owWWLXDZD91vLCsneLqLuiKjqYP+wimAS2gZUAgbyTfwrDB+C
         qwPpa9j31uPZBeENwn2R/HYyINtixRVg1eAlOS36bTKoNCBz5HOQXB+W5CVpMGVYyRNr
         sbodDlyO3fhk08+meYYnOC6BOF1d78P0tKGkG/ZBGduZmai0WycGwjHnXMl+4QM9wobe
         HKjQ==
X-Forwarded-Encrypted: i=2; AJvYcCVwRWOO93ES2u7yk5CCWTlsYkWvWzIS2tJvWgGnD1Moa3Q4+dHms1wEIhW7juyhnnR6Q7WGvOhZ22KLsmD+ZSaeFusUSRtL1Q==
X-Gm-Message-State: AOJu0YwF4k7DDjGcOAbEt4MxPzNTALOSvAsGFcOyl+SIuiDiItCQyioS
	cqOm4BeGGzqRn0DzptOMqcx5Apu1y0OJ0jJFOBn3m3urv/s5jnkge/E=
X-Google-Smtp-Source: AGHT+IHRCnHNHsqLNz9AXc5jl77F36Flj7HimKnNDeefUFIvirm5OvpFnfXoLUoC39juxg7nYMK+4w==
X-Received: by 2002:a05:6a20:4719:b0:1a0:bb45:415a with SMTP id ek25-20020a056a20471900b001a0bb45415amr3331998pzb.28.1708808458786;
        Sat, 24 Feb 2024 13:00:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1dc7:b0:298:e10d:b61a with SMTP id
 pd7-20020a17090b1dc700b00298e10db61als27315pjb.1.-pod-prod-03-us; Sat, 24 Feb
 2024 13:00:57 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXKU5mV0hwFCDA68hlTcAlvjmfVkxD1Uz7T4hqVQj3mmhgSWfqn0Zom6Uq7L1tcL+AmiHoAbqspjcmAHjTUWrdrPbSOwy73DAJ6Wg==
X-Received: by 2002:a17:902:d506:b0:1dc:90a7:65ef with SMTP id b6-20020a170902d50600b001dc90a765efmr991515plg.23.1708808457392;
        Sat, 24 Feb 2024 13:00:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708808457; cv=none;
        d=google.com; s=arc-20160816;
        b=alhRcreADeVj/M1drTRkcG82qEwhO3e0ZtamfUwqAvvxGCjW/KDap8e5pNqz9UGwNF
         R5dLUSz+IqSfrBGOCkkkpSzjnZ4lQFxeCyYk0C9Ygy0cYr/E+3yhklrFT7MqrA2e8FtZ
         4u5I/tB+o8qtl/iq29AzKGcT9gGN8+EBY08Igg9vqtHZz0le0jWyjoQvDSHzPZ3RBkYy
         ufCyAerOOJU06tg9jRBYJ8elTdMert6RyUJMQcR679zIkdITislr+88C9oqbxf04kUUE
         RUezByLc3EYQpbWRUCQhBPMG6xvuPzgsMkRTnZ+YCDZ28Lo3PXn1SJNHPFmz59sw7idQ
         JTIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:message-id:in-reply-to:subject:cc:to:from
         :date:dkim-signature;
        bh=X3wcsrUGLumHpSftRKJTOmQHGqRsK0TVAD3bFgayXNU=;
        fh=1DojiarueXfNtNEZaqfcjEsTwLT02a8hXwIvAHUSmdo=;
        b=KYJuutkEv7NGCbmb+6WqWiq5vDth9GDHsBIBMruZ3svPS1quDrQIFUWPoWZGzT56jY
         rzokD7V0F228hTt5vfUP3tZGGEF97kDt2LNQrtK6PimOj1IsOY5nL2hWoo+5spBS+V5l
         10BvINPt4fMLBbW74A0IGbxMWAeFQMHtSMlou0aSzweNsipArVizYNtTUzwm5VEnbgFO
         ZKmc99zq3eBylaDj2GbZSg9+6DjJXFoy6v912lwUQA6NX3yBBEu7d6nJlgWUvjtY+AD7
         JG/qyPEizg1WTwPYQHoktzvvgbenGmWauxhy76Br2gcJbnO+9KUml0tpZWiS+jyNR8FS
         80Cg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1+bNYSqe;
       spf=pass (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=rientjes@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x630.google.com (mail-pl1-x630.google.com. [2607:f8b0:4864:20::630])
        by gmr-mx.google.com with ESMTPS id m13-20020a17090ade0d00b002993c104736si226557pjv.0.2024.02.24.13.00.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 24 Feb 2024 13:00:57 -0800 (PST)
Received-SPF: pass (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::630 as permitted sender) client-ip=2607:f8b0:4864:20::630;
Received: by mail-pl1-x630.google.com with SMTP id d9443c01a7336-1dc744f54d0so127325ad.0
        for <kasan-dev@googlegroups.com>; Sat, 24 Feb 2024 13:00:57 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWQ/BSwlM28ni8ZkNUAHRyqvG4AXZP38bfyVuTzELWUnyPYf4b76J3aJDRGi/ExWDZkSwv68y1vbGIXNh8wszQ+rPMupjdCURitZQ==
X-Received: by 2002:a17:903:84b:b0:1dc:f0e:51 with SMTP id ks11-20020a170903084b00b001dc0f0e0051mr189957plb.17.1708808456663;
        Sat, 24 Feb 2024 13:00:56 -0800 (PST)
Received: from [2620:0:1008:15:ce41:1384:fbb2:c9bc] ([2620:0:1008:15:ce41:1384:fbb2:c9bc])
        by smtp.gmail.com with ESMTPSA id bx33-20020a056a02052100b005dc507e8d13sm1252883pgb.91.2024.02.24.13.00.55
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 24 Feb 2024 13:00:56 -0800 (PST)
Date: Sat, 24 Feb 2024 13:00:55 -0800 (PST)
From: "'David Rientjes' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
cc: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
    Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
    Andrew Morton <akpm@linux-foundation.org>, 
    Roman Gushchin <roman.gushchin@linux.dev>, 
    Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
    Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
    Alexander Potapenko <glider@google.com>, 
    Andrey Konovalov <andreyknvl@gmail.com>, 
    Dmitry Vyukov <dvyukov@google.com>, 
    Vincenzo Frascino <vincenzo.frascino@arm.com>, 
    Zheng Yejian <zhengyejian1@huawei.com>, 
    Xiongwei Song <xiongwei.song@windriver.com>, 
    Chengming Zhou <chengming.zhou@linux.dev>, linux-mm@kvack.org, 
    linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
    Steven Rostedt <rostedt@goodmis.org>
Subject: Re: [PATCH v2 1/3] mm, slab: deprecate SLAB_MEM_SPREAD flag
In-Reply-To: <20240223-slab-cleanup-flags-v2-1-02f1753e8303@suse.cz>
Message-ID: <a1d53915-7177-aa3b-6b2c-ae2dfcf7a83b@google.com>
References: <20240223-slab-cleanup-flags-v2-0-02f1753e8303@suse.cz> <20240223-slab-cleanup-flags-v2-1-02f1753e8303@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rientjes@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=1+bNYSqe;       spf=pass
 (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::630
 as permitted sender) smtp.mailfrom=rientjes@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Rientjes <rientjes@google.com>
Reply-To: David Rientjes <rientjes@google.com>
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

On Fri, 23 Feb 2024, Vlastimil Babka wrote:

> The SLAB_MEM_SPREAD flag used to be implemented in SLAB, which was
> removed.  SLUB instead relies on the page allocator's NUMA policies.
> Change the flag's value to 0 to free up the value it had, and mark it
> for full removal once all users are gone.
> 
> Reported-by: Steven Rostedt <rostedt@goodmis.org>
> Closes: https://lore.kernel.org/all/20240131172027.10f64405@gandalf.local.home/
> Reviewed-and-tested-by: Xiongwei Song <xiongwei.song@windriver.com>
> Reviewed-by: Chengming Zhou <chengming.zhou@linux.dev>
> Reviewed-by: Roman Gushchin <roman.gushchin@linux.dev>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Acked-by: David Rientjes <rientjes@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a1d53915-7177-aa3b-6b2c-ae2dfcf7a83b%40google.com.
