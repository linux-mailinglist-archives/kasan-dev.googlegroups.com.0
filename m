Return-Path: <kasan-dev+bncBCF5XGNWYQBRBA6BVKXAMGQERJ3BFZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id BF9818521BB
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 23:49:40 +0100 (CET)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-68c52361422sf53001816d6.3
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 14:49:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707778179; cv=pass;
        d=google.com; s=arc-20160816;
        b=tSOj+t6kHcjPeFZVv4ExpzU4BWqo2vE7FHP4h1/LtZqgrWIDsIHfKX0/nIYGOCGJ5V
         FlUtl22rlecKJgSW0ea0q41Uyp7FoFerVH42/0LQuSfB/hQEEswtyFWtWARd+jVpNq14
         VGQvGIwhPY5FdFbc0eZPvADiif8UgYf/oMfFAMZ5xHy6ZMD8EbzUz0rLeYdR9nE1/Y+0
         uXpc0wxBevL09RuB4MXJEqCtBLaFamIxY3Lc+YzjeSg/huPrho3Fhi228U6YkjoXiXoy
         9Ja/kai3ns/VEcUB4rwFa2MTCd3ESLEfFX46ViDs2QmaExZu/zrCM1cnWP5CLtEFwa15
         X1Yg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=yJzZ3jRYx7Lq0p0xMPWdTEQeA27GJdjxySDlCUOgUGo=;
        fh=RWvgPXZdlma+pdGi2SA2Ec0jwa4h08O2f+TQWdPUkn8=;
        b=TsIiihsqRNlt2q7fhl+FUNGPTE5Z1cP8Gba5utowtUHeK/jOcl2o6R/mzogm2Vps9P
         gQA3kx1A0Si1Mg0JD6+sJhsNWgmPHUHQ1xLJmDH3fWQLUpcU0ssIBinYl2siJtvUxRVJ
         PdzrKZWMPiqMTRqDZeBo0xOo0KXGDcHxKGcGomcXkrp9uvja9g9y78G47TtN7vd9kXwS
         rRt6SBcktaIyVFJTYIAFUgWhCR4ui3d4+kwwpoUu8Y4ol5v8siPna9ARHkOhBLw87huE
         i1hdN1SNtpnkBHlnJKf7r4Fwa/CwcLxR23JBwufdQkoS8oXDN7s0wWVzzrdOeXSSuoyo
         1HUQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=iabszL+t;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707778179; x=1708382979; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=yJzZ3jRYx7Lq0p0xMPWdTEQeA27GJdjxySDlCUOgUGo=;
        b=miQQbxQ9Q1ABeOsCkA53z21ovDKsn1G6LsTofoIo1zM3D3VOAJ1zFcSs9uIH+fOFWs
         E7RetGyFLglgyJs5Zee0/X75nmQX5hG6ClPU8T3t1IuT7j+9gUhbesAdnWZHXMklQ8vp
         nghs8sbaJ50SFs05S46XGOhNtq5ElpvnGo7PPsEM1DPph/suU8AidAuVu29sM0aRFxDc
         6LoYHLlVnxi1VXBlVb+69OoSs3N6RqgiEXT9WWE7bvfCXVe+FEdoi7c6dNhclaRT1oe3
         gHGavq3Mg5yB6nDh1VpySG01x+q2Uuu2qJiR/AVdL4+iVuLOJU4pIehMOs5yhHx9objf
         X8Xw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707778179; x=1708382979;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=yJzZ3jRYx7Lq0p0xMPWdTEQeA27GJdjxySDlCUOgUGo=;
        b=QIV8OfzvtF8QopoYbchPTDrJMHWrfErVB+ORs813xrlXnMF8vG3/r2k/1jacTLxWb5
         Xq9biJ/XFLjsZsDHE1W++kqYxmlJgCiuySSI8qvg4NcsYkrqHGwd3bOdhXkGE/ovZNW8
         ogoocRiEXHGIb+IwI2MMv/J6ARY0EaN89TJfBZK+guh+NEz6ckuZ6UTUbT2lwtwC5mUn
         yeCl9HOqCItaZUdR8VTo8fifDQ7ZQIcKNrZpQyrA+ssTdplgIEI7rl9hYXQF+8+fWh03
         q4i5G60ryIXvWY4XjSA5CbHIO5QxmvrCZsL0ge2A41X1oacTp8jEcjtUIvnFbJYHVb1m
         LEIw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW6iZETzRWboc7Hk6+cbkEMGqYEZtwFWxCKdt2M0WN5nKDjXgsB+p9QPrPbh83CvPAH1//evSJMqLUVSs16+amDKzWxd7GcbA==
X-Gm-Message-State: AOJu0YwBytjrNdXGsCzon6j+buO5dgdvny7YsGcKmRtjWa/KNVZYFMuo
	7O0LxxnTthd8zSn5XxywnTybEbf4sctQWMl10uGv2WkbrNy9Quiy
X-Google-Smtp-Source: AGHT+IH3mv8WR9L4OwUpRNwxGSbiZj+55R0V4nfEQKz/hNCPVSwkvriz1t4eLBdTnBxAOxweomh+xg==
X-Received: by 2002:a0c:e288:0:b0:68c:c623:1d8c with SMTP id r8-20020a0ce288000000b0068cc6231d8cmr8097081qvl.23.1707778179616;
        Mon, 12 Feb 2024 14:49:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:1c0b:b0:68c:8a1c:76a9 with SMTP id
 u11-20020a0562141c0b00b0068c8a1c76a9ls964339qvc.2.-pod-prod-08-us; Mon, 12
 Feb 2024 14:49:36 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVNgsNC7L6mmJfMablzS4oHp19KfY1kB38qt2V6hs2a+E9kKRMLPtxoU/tdf//Oh8sEILVRbXaLYNm8vsDLIwKbO6vNe8UOqJuOMw==
X-Received: by 2002:a1f:db03:0:b0:4bd:3606:c7aa with SMTP id s3-20020a1fdb03000000b004bd3606c7aamr3671068vkg.5.1707778176485;
        Mon, 12 Feb 2024 14:49:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707778176; cv=none;
        d=google.com; s=arc-20160816;
        b=ks87ZLQSRQ1qqLaXeCIFWl3he/PgMGPzW+XbFB3/l+2dpvD+EwyY9SrQ4IRzqSvLMi
         h+ts/9S7vt7C4VaMr45lU1WCP6KxM7dIKv20FOYrZqLjpBs/diXxQYjZ+FQIRKRXi7XI
         qjC/4pDzDokCeikA6KNxqW1xY0rl1B/OXeH0bXjHFb6ghUgErwBpLn90tuYV2YueNBhD
         sv6QKqSdAChoQFSbnUy97hH+/Qwf638N+t6ihqRB5zx6ZrRbTk1g0ZW/nsRt6dFHE15n
         g+XhYNCUXNEfy0Nlw9ZuyG8pNdKRuzsF5kd5r0Lq8W2dbR3sw1dSPdAsYfmPbrZTC+I9
         uBXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=xx+E2mv21N0lU1zbrbyeE8PV+0+SQ7K7DmnAXJKKlPc=;
        fh=pekqbHf+kgdVtPlvFrfM6gY7Eutn255QCzbMusTY+jA=;
        b=vwSfdlwquWIMbaDYK4ZYGPVW/dcB/tFKUViOQA1KXJEPgl+1BPFN7cLiTnTjwa4Ypt
         mxQ4X0cU8fAmQEec/wS80c+1/S5nB+E7zUP30lboFB3UQyfbyhN8ulV0/ZgxYJ8/IuDI
         9vtt9mBjnhgDPmioQIySyZX+D/5LJ4pk//WB+EZxcjX7hmiQgO454HgC5DplIQLtc62V
         8OyPC6twFNI7MwP4W7K++EEapiwF4XhjrJkDIJCMQ6jue96ufV0JSE4IzuFBqky2fGRo
         Y/Cyl9hFwGD+IQKkvLe/A3s2ZL7lmr428tSOh4NOsfKgqlzSiOMrDJL96mkYUHp3//cH
         E0SQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=iabszL+t;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
X-Forwarded-Encrypted: i=1; AJvYcCVwLlJktb0FgVTv9QVzKMulBk+8lAd3eymzvjvXx6f29HF3SfSojrGEaJUeWw40ev/MgQLC1rDOSVFuzSrnChH8blsa+QxeIxo2BQ==
Received: from mail-pl1-x629.google.com (mail-pl1-x629.google.com. [2607:f8b0:4864:20::629])
        by gmr-mx.google.com with ESMTPS id l34-20020a056122202200b004bd8843d8a7si715486vkd.2.2024.02.12.14.49.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 14:49:36 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::629 as permitted sender) client-ip=2607:f8b0:4864:20::629;
Received: by mail-pl1-x629.google.com with SMTP id d9443c01a7336-1d76671e5a4so30873105ad.0
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 14:49:36 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWLNMYxNeAZjJSaSoKTaxrWfPpBa45LKqq9QqoNMTW1g8hur9Qdl5i/gbUqtK+kVayLG2odf6VHZNLiMSBzXH7wP4Q8SzsPe/KTJg==
X-Received: by 2002:a17:902:c40c:b0:1db:28bd:2949 with SMTP id k12-20020a170902c40c00b001db28bd2949mr2209227plk.0.1707778175528;
        Mon, 12 Feb 2024 14:49:35 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVzBGKmQCADr7SqFCb9B/XJ1a8IPhel9FdTOf1c94uoEoK68yRJ15+p01MxjPjBrzrxJ1LmN1dq3tgQEjrv6uhCkGudBT36hspST5r7HPiCfIpGUIjeLKG3UuZnRNlsaHN1rhS05svyBIcjHk89C6MmJorYo/r1oWVj60PAZbA4xdIzVaWsrRk0pKGHSS5VRPqhZ/m25DiZ0I27J6O6WJosSlZuoHdQx1rf256CDIvnlandU9frw0q2QikKecFUd62eKJv2Oep/I5hvX5DVnlii1V2N3FeM8VEbSaaiUC/vUUCtB15U4kJguTpV3HbxGVzbR0JR0pTiQ0t/easp14XiaBRzlnZSMl3xWtJtf7iKSQM3Rn5i6BH0Fl9qjDeJVQFR5iZ5DJFZjP4cfGW3Kah2udMc1KI+OkoWo3VhChcHNe+J4fLzynSzUuDpXeFkYUo1zfKj3K8ED6Vb+4Pz8WpubPUstU5afuX4v0kztyCn0G3AwJc5hcujndob35qwI2SQF2A5pcPCRLALJU85CK4wpfVmSrbHEMZUSpAJit36HiXLFsDmZPEdTMamsdEEiaJy3UuD4+f/+CsdeDG3fz91GjYmmNyA2pKjFlO1swBuj+ge8sUbDlkBaBWrugjC6stgC7WMj/UxUy1dl9NQQsYSagfFDE7BW8+83llOIKhZzq+ieoqbJ2LZagQYi6zroajziajjAtttJ5ZXkQPdiDBlvQfB1qzfFOTqLlY4xZJ+4NijkiRTaRVYCbb8pW9MyfIoas/cfCcGFcgYq06/VgLxSuaf3+umaAG40rlQYx+1qOzpxyZgmYPK9rLDIawYXfI1IhO4t4+QRLW3cDNyG5CFcUIZdDkyqGEHYeaKCtPvHUPZ+07unOgyoiNNBlWXiO22DQHeLdYkWpTGFnQGj5M6X+PK8EzSwafBfAFpdcnovJNm+XvgSUF2YFBlIGoArp4zdR
 XMkJ0P3+1w3M6FA0X23d6LYkhZ4n/ekiilEalf9QkHPIo75Ce3IuaCYffBdOkKdwkpkCHJQvqFuEDhi0ik/uTXUy0eqnA2GlLVPHKbz/boqe7dFmoDt4waGDgYaNXRMK9/rU4npvdKlCqEKXa73v2SCBsEHihs6jVPVIMRDCs6w21e6T1dFws4SG57RBRAnmHB/Cmp6L9VbHX8qj3k4zy9soAR8ZTPXudS7V2X1xaC4JVyIwIAX4P3AerYiY1hIR6Ns7eDGWsl2i8uMAtg+MQAsuPpqI1GJtkpseTgpGBLbqjccOQFuXKUFO363qIHUlrJISUBQQOJoRUGVpNV4FDjmyA6QZBFEiktubQEfs50HtkdvxLSybdjNuM06RyUyxn3eeVKUV0CgiYfPBKl3A8vRzdsjfSlrvI+cmgn1BLFjV5aTr/nTSQ3LctN+wk=
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id kr7-20020a170903080700b001da11733477sm850131plb.75.2024.02.12.14.49.34
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Feb 2024 14:49:34 -0800 (PST)
Date: Mon, 12 Feb 2024 14:49:34 -0800
From: Kees Cook <keescook@chromium.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
	peterz@infradead.org, juri.lelli@redhat.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	ndesaulniers@google.com, vvvvvv@google.com,
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	iommu@lists.linux.dev, linux-arch@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH v3 34/35] codetag: debug: introduce OBJEXTS_ALLOC_FAIL to
 mark failed slab_ext allocations
Message-ID: <202402121448.AF0AA8E@keescook>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-35-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240212213922.783301-35-surenb@google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=iabszL+t;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::629
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Mon, Feb 12, 2024 at 01:39:20PM -0800, Suren Baghdasaryan wrote:
> If slabobj_ext vector allocation for a slab object fails and later on it
> succeeds for another object in the same slab, the slabobj_ext for the
> original object will be NULL and will be flagged in case when
> CONFIG_MEM_ALLOC_PROFILING_DEBUG is enabled.
> Mark failed slabobj_ext vector allocations using a new objext_flags flag
> stored in the lower bits of slab->obj_exts. When new allocation succeeds
> it marks all tag references in the same slabobj_ext vector as empty to
> avoid warnings implemented by CONFIG_MEM_ALLOC_PROFILING_DEBUG checks.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> ---
>  include/linux/memcontrol.h |  4 +++-
>  mm/slab.h                  | 25 +++++++++++++++++++++++++
>  mm/slab_common.c           | 22 +++++++++++++++-------
>  3 files changed, 43 insertions(+), 8 deletions(-)
> 
> diff --git a/include/linux/memcontrol.h b/include/linux/memcontrol.h
> index 2b010316016c..f95241ca9052 100644
> --- a/include/linux/memcontrol.h
> +++ b/include/linux/memcontrol.h
> @@ -365,8 +365,10 @@ enum page_memcg_data_flags {
>  #endif /* CONFIG_MEMCG */
>  
>  enum objext_flags {
> +	/* slabobj_ext vector failed to allocate */
> +	OBJEXTS_ALLOC_FAIL = __FIRST_OBJEXT_FLAG,
>  	/* the next bit after the last actual flag */
> -	__NR_OBJEXTS_FLAGS  = __FIRST_OBJEXT_FLAG,
> +	__NR_OBJEXTS_FLAGS  = (__FIRST_OBJEXT_FLAG << 1),
>  };
>  
>  #define OBJEXTS_FLAGS_MASK (__NR_OBJEXTS_FLAGS - 1)
> diff --git a/mm/slab.h b/mm/slab.h
> index cf332a839bf4..7bb3900f83ef 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -586,9 +586,34 @@ static inline void mark_objexts_empty(struct slabobj_ext *obj_exts)
>  	}
>  }
>  
> +static inline void mark_failed_objexts_alloc(struct slab *slab)
> +{
> +	slab->obj_exts = OBJEXTS_ALLOC_FAIL;

Uh, does this mean slab->obj_exts is suddenly non-NULL? Is everything
that accesses obj_exts expecting this?

-Kees

> +}
> +
> +static inline void handle_failed_objexts_alloc(unsigned long obj_exts,
> +			struct slabobj_ext *vec, unsigned int objects)
> +{
> +	/*
> +	 * If vector previously failed to allocate then we have live
> +	 * objects with no tag reference. Mark all references in this
> +	 * vector as empty to avoid warnings later on.
> +	 */
> +	if (obj_exts & OBJEXTS_ALLOC_FAIL) {
> +		unsigned int i;
> +
> +		for (i = 0; i < objects; i++)
> +			set_codetag_empty(&vec[i].ref);
> +	}
> +}
> +
> +
>  #else /* CONFIG_MEM_ALLOC_PROFILING_DEBUG */
>  
>  static inline void mark_objexts_empty(struct slabobj_ext *obj_exts) {}
> +static inline void mark_failed_objexts_alloc(struct slab *slab) {}
> +static inline void handle_failed_objexts_alloc(unsigned long obj_exts,
> +			struct slabobj_ext *vec, unsigned int objects) {}
>  
>  #endif /* CONFIG_MEM_ALLOC_PROFILING_DEBUG */
>  
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index d5f75d04ced2..489c7a8ba8f1 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -214,29 +214,37 @@ int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
>  			gfp_t gfp, bool new_slab)
>  {
>  	unsigned int objects = objs_per_slab(s, slab);
> -	unsigned long obj_exts;
> -	void *vec;
> +	unsigned long new_exts;
> +	unsigned long old_exts;
> +	struct slabobj_ext *vec;
>  
>  	gfp &= ~OBJCGS_CLEAR_MASK;
>  	/* Prevent recursive extension vector allocation */
>  	gfp |= __GFP_NO_OBJ_EXT;
>  	vec = kcalloc_node(objects, sizeof(struct slabobj_ext), gfp,
>  			   slab_nid(slab));
> -	if (!vec)
> +	if (!vec) {
> +		/* Mark vectors which failed to allocate */
> +		if (new_slab)
> +			mark_failed_objexts_alloc(slab);
> +
>  		return -ENOMEM;
> +	}
>  
> -	obj_exts = (unsigned long)vec;
> +	new_exts = (unsigned long)vec;
>  #ifdef CONFIG_MEMCG
> -	obj_exts |= MEMCG_DATA_OBJEXTS;
> +	new_exts |= MEMCG_DATA_OBJEXTS;
>  #endif
> +	old_exts = slab->obj_exts;
> +	handle_failed_objexts_alloc(old_exts, vec, objects);
>  	if (new_slab) {
>  		/*
>  		 * If the slab is brand new and nobody can yet access its
>  		 * obj_exts, no synchronization is required and obj_exts can
>  		 * be simply assigned.
>  		 */
> -		slab->obj_exts = obj_exts;
> -	} else if (cmpxchg(&slab->obj_exts, 0, obj_exts)) {
> +		slab->obj_exts = new_exts;
> +	} else if (cmpxchg(&slab->obj_exts, old_exts, new_exts) != old_exts) {
>  		/*
>  		 * If the slab is already in use, somebody can allocate and
>  		 * assign slabobj_exts in parallel. In this case the existing
> -- 
> 2.43.0.687.g38aa6559b0-goog
> 

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202402121448.AF0AA8E%40keescook.
