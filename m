Return-Path: <kasan-dev+bncBC7OD3FKWUERBSM64CUQMGQE5X5UNEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id EDEBE7D5ABA
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 20:39:07 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-3fe182913c5sf28243325e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 11:39:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698172747; cv=pass;
        d=google.com; s=arc-20160816;
        b=g3iITsCiHDHwLjuuaOXE3yVVUqRSLaWW0MgiF9+T/lD5pXWs1DUf3WgM77rGAR+dsa
         9eO6W6NiCX25GrW57xRlBs7lwus0i16vhTs2PHzaah+xOJbZfB6eJRESI/nZp+6TR/xp
         MVxgI1tg1g//z5kl9M8E/8z9eMe6v5QNpF8WVOaYIzBFSdx/ODvvtu9MA538s0dDV6DG
         H9/bzYXRYUGmMFYWunOgtZMYEP8F97PC2atf68mwOvNgoSQpRjwdbG5XLVKlQXw3acEi
         XPxpnuuQVBp46A6gDfdJCZB6fr0GHNn0eBAIy8mqJ8hWpfPrAGp6mgUt977DCz6o5sc/
         ALqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=LqjVfKW2NuxhgaKnjO2P8QJFBvocDeSsuDzz4mAnwFI=;
        fh=FfoU0ET5QwnTqqxPFnIysHogbCP4U9SjwY4sZfirvBU=;
        b=T1dXsuKc1YDcyPyjMAWhK6rS8uWo69gNIjorfJaORopQ6D+6mHtUw+FZnCHfmEQxcx
         uZPZmfEPDecgBazLmp2v/qJSMh+8QonhkwpCTakiAkLGlwVCszYGhQnOxvwiPC0FqGvf
         weZGy6WPufHFPkTM0aEIg3SpSNKMusOO74xmpUnBrIXlOhhMDLOvCUfjL17u28yjQgSz
         pLna3FsAkxdg3khm6GvryX1kNWHs9ONXQMq8i/UYXTtaTPzOBvXrBO+xUrQfgD7TKe9q
         Z9NYeuHmQyvJvY5V0fzaRLpM+d6fRtrtu3paXg+29AhIpqODokI8S+JiplUZKBEQbkKw
         ZB7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="tovla/K8";
       spf=pass (google.com: domain of surenb@google.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698172747; x=1698777547; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LqjVfKW2NuxhgaKnjO2P8QJFBvocDeSsuDzz4mAnwFI=;
        b=bXEQl3zaliaXBG49DSTQYCEoG0hZpNSRD692+4zVJqUttmitjVHbV0vvXqFqGXNMB2
         Jj5/D1iUiiJ00XxnirLZU/29g6NluHpJflujh1D5/ZapumJ7EfNP/eH0P0GP0oD/OG7K
         /d0XvfSxTcBNA6dmJ8l12nH7sgzo1ZG7KkObNLVzIKWU+RZSSS2jeWRRK8BjaWuIh1cH
         4x+ipxHGzcrjheHPJsO9leWuo8EegKzsrPNRI5GbS+vg1jC5wD4QeZG2atoawyuz5aVK
         Iy9AWsRc8bXObVhOwU1J2XFyU5adPS49fagx8O/WcUjnLSVEmJ6hJpubzSdiCyEe2z2N
         +KRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698172747; x=1698777547;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=LqjVfKW2NuxhgaKnjO2P8QJFBvocDeSsuDzz4mAnwFI=;
        b=Pn4z/Vcg9S/vM4bs+7IrFiGloYH7qDrNbXi4tt8DedeQN6vdo//EMYbcTlPwI4WJrN
         BV9ClZEK5cY/Jbgfx+B/GO6yf5fH6mXP+YEBKe8kmN0CTjvwnb13/Nlruq5WO1nJ67HT
         rwM28ct8Z2L2d64aYSXANGLCVXlX5edBCcPHxT9xQvOncezlwhK3HSK+M4Tj9Uy6mPff
         h6xz3CrmiLG6KMUXnPi75VCqWKuw/PAUoTI8ZZBCH4qqcq9IhZyh+xqrqmEDPbUUT+jQ
         JXiL8xutH6OPgSl4C1DHfdGukimDlJh6vwBPFOziQrqYpMgnmcwBujJSwFubISa2/0X2
         Rp+w==
X-Gm-Message-State: AOJu0Yw5dB0RM3hxPQvlFkevK1LY8WzJmkzJb+dR9DlhzbQeJ5jesXvB
	dHt7UE1sWt9liLkciq0Ly8U=
X-Google-Smtp-Source: AGHT+IEmtveflJ0Qf2vBLi7LRaZ+gGFYAwoutQVPlrcMlewYaYpTH/633Snpm2Cdrxc3WPqvLxL4bw==
X-Received: by 2002:a05:600c:3583:b0:408:4095:6f0c with SMTP id p3-20020a05600c358300b0040840956f0cmr10833724wmq.38.1698172746056;
        Tue, 24 Oct 2023 11:39:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c1d:b0:407:67a8:8d2a with SMTP id
 j29-20020a05600c1c1d00b0040767a88d2als1882810wms.0.-pod-prod-01-eu; Tue, 24
 Oct 2023 11:39:04 -0700 (PDT)
X-Received: by 2002:a05:600c:4e8c:b0:401:bf56:8ba6 with SMTP id f12-20020a05600c4e8c00b00401bf568ba6mr9958026wmq.28.1698172744330;
        Tue, 24 Oct 2023 11:39:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698172744; cv=none;
        d=google.com; s=arc-20160816;
        b=gWicjDrmDRZjodkm0je1T/4lL63USOaOs3DBztV6z74bp1lfRFUkCz/EliPfHAgDIZ
         kwjwJgAxfwXDNC+WNKUclh1giWmQDwxxboXLPUuATikV8t9uxdXa/X9fFKh3EUwfkH9j
         D5lwSRwQVnj4xUqsox1iOqPHV/miBoS12pXDH15twmneWxtOAqBD8Xeog8UbipQ91IDw
         WYoxrT6DuS63pgyLrSwvgFJQbe/DAAw6Wf6Bck/OWIzqyFeCHf98ed2qbKH+N2AtgVTT
         YCjkw7N4tnpVmkyop/lBknYt6lZXmrWP49D4vlLWH11DO1JjjKY4AIdbkrI5lDvVKi4Q
         Wl3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=kYl/hPQ1QO/qnjhfpaigT8V90o1Z/zrFBqqxchQb6PA=;
        fh=FfoU0ET5QwnTqqxPFnIysHogbCP4U9SjwY4sZfirvBU=;
        b=GonV6io+tJernO0jRri/xOMv7jK8IWB6viPXjMgh0WXRETKTyCcnWZ0M76fT7C6fUw
         bR168LSlcYejDfpAllQZ2IhAZciV66GkU1SPEP8xQliO34GcQXrbH9MKKGq0a30jZwWh
         lPNnhiNZEAVnSJf/GtBWDuQ1SQON+1O6WONbFf6vm717pZJBC3y2vitbqumd/UOfMcaF
         NwopQ7d8cdPbxLy1ZnZ4mZak5wI33NCfDajMcFWzVpFI+u9qM6bFIfM4w8Y1e+6yP+BZ
         25PO5giwBEbZTr3HdOD1tjsSImnUOmLMtj3SyzbMilrY1VAoNpOmLRo6f35DU8sn6y0I
         g/Cw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="tovla/K8";
       spf=pass (google.com: domain of surenb@google.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42c.google.com (mail-wr1-x42c.google.com. [2a00:1450:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id n16-20020a05600c501000b00404ca34ab7csi29534wmr.1.2023.10.24.11.39.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 11:39:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2a00:1450:4864:20::42c as permitted sender) client-ip=2a00:1450:4864:20::42c;
Received: by mail-wr1-x42c.google.com with SMTP id ffacd0b85a97d-31c5cac3ae2so3490164f8f.3
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 11:39:04 -0700 (PDT)
X-Received: by 2002:adf:fe8a:0:b0:32d:ad05:906c with SMTP id
 l10-20020adffe8a000000b0032dad05906cmr10224110wrr.3.1698172743492; Tue, 24
 Oct 2023 11:39:03 -0700 (PDT)
MIME-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com> <ZTgM74EapT9mea2l@P9FQF9L96D.corp.robot.car>
In-Reply-To: <ZTgM74EapT9mea2l@P9FQF9L96D.corp.robot.car>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 24 Oct 2023 11:38:47 -0700
Message-ID: <CAJuCfpGNQpFLnUsEpGgiDmOBW17RXJ3B-u2+ogi7NNhfi-gBLQ@mail.gmail.com>
Subject: Re: [PATCH v2 00/39] Memory allocation profiling
To: Roman Gushchin <roman.gushchin@linux.dev>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, mgorman@suse.de, dave@stgolabs.net, 
	willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	ldufour@linux.ibm.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="tovla/K8";       spf=pass
 (google.com: domain of surenb@google.com designates 2a00:1450:4864:20::42c as
 permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Tue, Oct 24, 2023 at 11:29=E2=80=AFAM Roman Gushchin
<roman.gushchin@linux.dev> wrote:
>
> On Tue, Oct 24, 2023 at 06:45:57AM -0700, Suren Baghdasaryan wrote:
> > Updates since the last version [1]
> > - Simplified allocation tagging macros;
> > - Runtime enable/disable sysctl switch (/proc/sys/vm/mem_profiling)
> > instead of kernel command-line option;
> > - CONFIG_MEM_ALLOC_PROFILING_BY_DEFAULT to select default enable state;
> > - Changed the user-facing API from debugfs to procfs (/proc/allocinfo);
> > - Removed context capture support to make patch incremental;
> > - Renamed uninstrumented allocation functions to use _noprof suffix;
> > - Added __GFP_LAST_BIT to make the code cleaner;
> > - Removed lazy per-cpu counters; it turned out the memory savings was
> > minimal and not worth the performance impact;
>
> Hello Suren,
>
> > Performance overhead:
> > To evaluate performance we implemented an in-kernel test executing
> > multiple get_free_page/free_page and kmalloc/kfree calls with allocatio=
n
> > sizes growing from 8 to 240 bytes with CPU frequency set to max and CPU
> > affinity set to a specific CPU to minimize the noise. Below is performa=
nce
> > comparison between the baseline kernel, profiling when enabled, profili=
ng
> > when disabled and (for comparison purposes) baseline with
> > CONFIG_MEMCG_KMEM enabled and allocations using __GFP_ACCOUNT:
> >
> >                         kmalloc                 pgalloc
> > (1 baseline)            12.041s                 49.190s
> > (2 default disabled)    14.970s (+24.33%)       49.684s (+1.00%)
> > (3 default enabled)     16.859s (+40.01%)       56.287s (+14.43%)
> > (4 runtime enabled)     16.983s (+41.04%)       55.760s (+13.36%)
> > (5 memcg)               33.831s (+180.96%)      51.433s (+4.56%)
>
> some recent changes [1] to the kmem accounting should have made it quite =
a bit
> faster. Would be great if you can provide new numbers for the comparison.
> Maybe with the next revision?
>
> And btw thank you (and Kent): your numbers inspired me to do this kmemcg
> performance work. I expect it still to be ~twice more expensive than your
> stuff because on the memcg side we handle separately charge and statistic=
s,
> but hopefully the difference will be lower.

Yes, I saw them! Well done! I'll definitely update my numbers once the
patches land in their final form.

>
> Thank you!

Thank you for the optimizations!

>
> [1]:
>   patches from next tree, so no stable hashes:
>     mm: kmem: reimplement get_obj_cgroup_from_current()
>     percpu: scoped objcg protection
>     mm: kmem: scoped objcg protection
>     mm: kmem: make memcg keep a reference to the original objcg
>     mm: kmem: add direct objcg pointer to task_struct
>     mm: kmem: optimize get_obj_cgroup_from_current()

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpGNQpFLnUsEpGgiDmOBW17RXJ3B-u2%2Bogi7NNhfi-gBLQ%40mail.gmai=
l.com.
