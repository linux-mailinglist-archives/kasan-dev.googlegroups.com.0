Return-Path: <kasan-dev+bncBDK7LR5URMGRBB7YVGNAMGQEWT5ZFAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1543A5FF96E
	for <lists+kasan-dev@lfdr.de>; Sat, 15 Oct 2022 11:23:21 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id c3-20020a7bc843000000b003b486fc6a40sf3279464wml.7
        for <lists+kasan-dev@lfdr.de>; Sat, 15 Oct 2022 02:23:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665825800; cv=pass;
        d=google.com; s=arc-20160816;
        b=VCeXrqsxpGqGsHfIUdkAm+n1yYE/OIRNLXAr0+y5SDIN2MPRgWIy0gig1NtkT7jztM
         thk8Dg58RwnOGQiBNc+hdAl3vpBqLCfimuXjwrZIYbsqcMz9hZaqJZl4IsKZkE1kFP41
         5VkxU8osanVDcSiw/Ak0nAZfCNuiJFMTffqli1zPjaPM+6OiJ7gL08jNJp8vcDBTj9Xq
         7JZ+Q52Fjy381LyjRQWibmLq7VeWXk1jXfe3P3MQEnuTZmNWWIi/sCYmJp5a9UYiczvs
         Bz1oRg6DReYQoEZDv/bE05OOgxJKsoAjXsS4LsIwejAZSl8jIvl5JVuZGAoG3MBEHW01
         v0/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:date:from:sender
         :dkim-signature:dkim-signature;
        bh=ga7v1rpLYGoERQ3w7tmNU9e4ABSUJuaQL4g9f9+iVgs=;
        b=us2i7vLgBfNNbzoSKzUHVvOMiJ3Fo2bijFAqPzTpZxywS8v09nAxL5fkg7nb2iz8cQ
         ITXWj7qaODyOJXKqIcYHIDhB5C5qNawFHVRQNK2ZfrknpR845jcHZLSvjRic2YKtHAZO
         FMkAy/0yCm2r07lGOJH+x6mvRW0uQPmQTe/eT5oM19Akd/ZvkR0GK+m4tKi3+ZCfoCXA
         TLlw1M0ITn3RfIGWfLctvbvaHD2Lq7/QFKZUHW4pDkqFIUoHGV+u5xiVFizwZnOWSPTt
         TkHbsn9Cj8Fd3FO67r8Jr6VaWXEXuW1EpsKMEqIFZQbWudquHDeYDGYEqWcBp90zUFm8
         WsfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=SHvrsXqq;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ga7v1rpLYGoERQ3w7tmNU9e4ABSUJuaQL4g9f9+iVgs=;
        b=drhomaupfpYiedciL/2acdEHYLnzOwf0C6DsD+b13gLu1TmXn5cKx5wnE0a9Uk+Tl7
         Fu1eJYXU65J0y6kl7trLt1c+T/od/Hpea2YknHQZtB5Kbx3Q5Z51+vpLGSKtzHQofdjf
         +hX55NmATrO4GCNJq1vr/K9mZ55KNtyS482s4VXuoouBA7Tva0QlxelW7j+sJe0THz18
         EE+Zq0/E4bw2gUf/oT0a+j6ZJnxMTGi5VX6vfG2+cxlJShMo7WVuhgeKFrPzoLhzG2pc
         fJr9PvI1BPI/tFFo0lZdxrV3iaaXOusTAwPaCIEpTTaMbdjBVtI9k0xlEp6onn9787z/
         1K4A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=ga7v1rpLYGoERQ3w7tmNU9e4ABSUJuaQL4g9f9+iVgs=;
        b=d3no0R4DMvqrlEHlU//uFbv1x1KOCD407rfS5MdKJezN4F3mMRaZPEMyiSj8499npe
         skGWEVTVbF6oHYTcc9NQxhhOACkv86I3/aLSVA17Ie9ltsZsls9x3iYsSUxf/kIjnKwC
         BMATyeoR7iWade+6BXvhcfhV7iPjlXBd3WfJzwRghdNd0C3zOiIQO3OGuTEEkjWT948t
         Tr4Lc8W4zqsEn3DzDM+w8HFeFb4Z5b69Yd3q84Mq2hMpZH1tbiqxOcEV4/RoE8YwGF3x
         ayTIA6amK7G9uYq6IgG+H/IK2W+6bhKBM8pl7ZwFJpDTVAqc3glNc7JRkuYCuCBKZ2cB
         Cr0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ga7v1rpLYGoERQ3w7tmNU9e4ABSUJuaQL4g9f9+iVgs=;
        b=JcmesUWn85zrkU65v/Nf4TzRHvVumImqGNZn3UCxedn8H2oehMQvnXqFjKuvIEvKHb
         E0ty6nV1qtnSpcZhnih9aFKzPhbFAbFC2HVxf9Bl9g0+ktfrjwa0RiSmt1veHjw89jwp
         zb3nCebtLD7TEqiUR7vPc1ZH/gVxehZ5B/nPmp8meAT5NFUOjDyJBVuImi+r36uCb2+g
         kz5hKHCzobtxRjK6BJSPHPI8U+Dx6YDzXeZWV9H/sxsJteXJqP0KU4pEkQPKhVNHcSgb
         LUCfIQyDX1QH11nUd8UCb+ihY7SY3yvWEILzIasPtdLuntaBFKTYFYtun+QLTuiGamJt
         WxGg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1/LmD4vG2SlBpDe0pQTpyvANsWmj/5x/sXdZA5LIZFeQCTKxT/
	ZU05Q2xN+dmWlEFiI2l24DA=
X-Google-Smtp-Source: AMsMyM47u4tCOGrF5mJOtoTGIsLqj34xZLJwgJaWDY+p9aoxRDum2BLB6lYHgG8+0Gdc/4t+nVh6DQ==
X-Received: by 2002:a05:6000:a1b:b0:22e:49e0:7ce3 with SMTP id co27-20020a0560000a1b00b0022e49e07ce3mr1024676wrb.66.1665825800337;
        Sat, 15 Oct 2022 02:23:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d20e:0:b0:228:ddd7:f40e with SMTP id j14-20020adfd20e000000b00228ddd7f40els11861343wrh.3.-pod-prod-gmail;
 Sat, 15 Oct 2022 02:23:19 -0700 (PDT)
X-Received: by 2002:adf:c582:0:b0:22b:3c72:6b81 with SMTP id m2-20020adfc582000000b0022b3c726b81mr1019986wrg.320.1665825799236;
        Sat, 15 Oct 2022 02:23:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665825799; cv=none;
        d=google.com; s=arc-20160816;
        b=v20gm19cePSJ/9hkiS+DFRxozkUXgPanoeYkzecGtLmklChOt0AJ+tNRv1N671qRHE
         ud2lQ/s+A4Crb83fSkFz5z4oCKPnOd+Do9mmDuacDpOaAdGqyxe8bqSL7ar3nZKfd5mG
         OMZ4KhtkIqIsQHdKHP1nY96Gb11QHQAAwCOT/nVePSZQTeE39p+lDzdZ5kw8VdgVdNxA
         J7Uu7vbHeFYzQn9mNqs5aje+SYpfRhY+iaveVPNSlg59fSR2AEdgiSXJ5Havg3X+i//z
         hRSUTlJhsTlYFN6xqtiwc7eaNNl6AKlH0RxobplpXZiBfQYS+b8Owhlmo+rGT26YcZwB
         OJkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:date:from:dkim-signature;
        bh=MYXJEzIwLvn5K4p0xa4MarpR6odk5pnBKyc18VUK7qE=;
        b=0JuUKH0ppTKW6RmgmYgU1358oBJNob/LnRRxBYXE5fnUP2dfMJJjZtFfRDy2evEasc
         4HhnK6VT1L81OszVPpvEtyAH52WlGhkPIxJaqjQbmmpwu+od6WIu5f4rqOXJ0nKmAi18
         9xlW5acSHPP4Ksryc5vvwUzUdZNobYmJfSv/irZi6AXeOlkcewQU+/EOMkTJQ/UHwQwN
         LIjZkNDs/E4S6ce/2eu+H49EWCMw0pz58WhUOnvNMm2O/KnrQNkH+J88SSoqJSPM1Slz
         F+EK/1pw1j9R2ozcX2K+Stw3ayJAspx3CRKcSJlttFv4FW51kBMVTKoFconLfwKrfTsu
         G4oA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=SHvrsXqq;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x634.google.com (mail-ej1-x634.google.com. [2a00:1450:4864:20::634])
        by gmr-mx.google.com with ESMTPS id j23-20020a05600c1c1700b003a66dd18895si540570wms.4.2022.10.15.02.23.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 15 Oct 2022 02:23:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::634 as permitted sender) client-ip=2a00:1450:4864:20::634;
Received: by mail-ej1-x634.google.com with SMTP id d26so15063968eje.10
        for <kasan-dev@googlegroups.com>; Sat, 15 Oct 2022 02:23:19 -0700 (PDT)
X-Received: by 2002:a17:906:846e:b0:78d:ed3c:edfa with SMTP id hx14-20020a170906846e00b0078ded3cedfamr1386124ejc.515.1665825798830;
        Sat, 15 Oct 2022 02:23:18 -0700 (PDT)
Received: from pc636 (49-224-201-31.ftth.glasoperator.nl. [31.201.224.49])
        by smtp.gmail.com with ESMTPSA id u22-20020a056402111600b00458dc7e8ecasm3289631edv.72.2022.10.15.02.23.17
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 15 Oct 2022 02:23:18 -0700 (PDT)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Sat, 15 Oct 2022 11:23:17 +0200
To: David Hildenbrand <david@redhat.com>
Cc: Uladzislau Rezki <urezki@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com
Subject: Re: KASAN-related VMAP allocation errors in debug kernels with many
 logical CPUS
Message-ID: <Y0p8BZIiDXLQbde/@pc636>
References: <8aaaeec8-14a1-cdc4-4c77-4878f4979f3e@redhat.com>
 <Yz711WzMS+lG7Zlw@pc636>
 <9ce8a3a3-8305-31a4-a097-3719861c234e@redhat.com>
 <Y0BHFwbMmcIBaKNZ@pc636>
 <6d75325f-a630-5ae3-5162-65f5bb51caf7@redhat.com>
 <Y0QNt5zAvrJwfFk2@pc636>
 <478c93f5-3f06-e426-9266-2c043c3658da@redhat.com>
 <Y0bs97aVCH7SOqwX@pc638.lan>
 <e397d8aa-17a5-299b-2383-cfb01bd7197e@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <e397d8aa-17a5-299b-2383-cfb01bd7197e@redhat.com>
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=SHvrsXqq;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::634 as
 permitted sender) smtp.mailfrom=urezki@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com
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

> > > 
> > OK. It is related to a module vmap space allocation when a module is
> > inserted. I wounder why it requires 2.5MB for a module? It seems a lot
> > to me.
> > 
> 
> Indeed. I assume KASAN can go wild when it instruments each and every memory
> access.
> 
> > > 
> > > Really looks like only module vmap space. ~ 1 GiB of vmap module space ...
> > > 
> > If an allocation request for a module is 2.5MB we can load ~400 modules
> > having 1GB address space.
> > 
> > "lsmod | wc -l"? How many modules your system has?
> > 
> 
> ~71, so not even close to 400.
> 
> > > What I find interesting is that we have these recurring allocations of similar sizes failing.
> > > I wonder if user space is capable of loading the same kernel module concurrently to
> > > trigger a massive amount of allocations, and module loading code only figures out
> > > later that it has already been loaded and backs off.
> > > 
> > If there is a request about allocating memory it has to be succeeded
> > unless there are some errors like no space no memory.
> 
> Yes. But as I found out we're really out of space because module loading
> code allocates module VMAP space first, before verifying if the module was
> already loaded or is concurrently getting loaded.
> 
> See below.
> 
> [...]
> 
> > I wrote a small patch to dump a modules address space when a fail occurs:
> > 
> > <snip v6.0>
> > diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> > index 83b54beb12fa..88d323310df5 100644
> > --- a/mm/vmalloc.c
> > +++ b/mm/vmalloc.c
> > @@ -1580,6 +1580,37 @@ preload_this_cpu_lock(spinlock_t *lock, gfp_t gfp_mask, int node)
> >   		kmem_cache_free(vmap_area_cachep, va);
> >   }
> > +static void
> > +dump_modules_free_space(unsigned long vstart, unsigned long vend)
> > +{
> > +	unsigned long va_start, va_end;
> > +	unsigned int total = 0;
> > +	struct vmap_area *va;
> > +
> > +	if (vend != MODULES_END)
> > +		return;
> > +
> > +	trace_printk("--- Dump a modules address space: 0x%lx - 0x%lx\n", vstart, vend);
> > +
> > +	spin_lock(&free_vmap_area_lock);
> > +	list_for_each_entry(va, &free_vmap_area_list, list) {
> > +		va_start = (va->va_start > vstart) ? va->va_start:vstart;
> > +		va_end = (va->va_end < vend) ? va->va_end:vend;
> > +
> > +		if (va_start >= va_end)
> > +			continue;
> > +
> > +		if (va_start >= vstart && va_end <= vend) {
> > +			trace_printk(" va_free: 0x%lx - 0x%lx size=%lu\n",
> > +				va_start, va_end, va_end - va_start);
> > +			total += (va_end - va_start);
> > +		}
> > +	}
> > +
> > +	spin_unlock(&free_vmap_area_lock);
> > +	trace_printk("--- Total free: %u ---\n", total);
> > +}
> > +
> >   /*
> >    * Allocate a region of KVA of the specified size and alignment, within the
> >    * vstart and vend.
> > @@ -1663,10 +1694,13 @@ static struct vmap_area *alloc_vmap_area(unsigned long size,
> >   		goto retry;
> >   	}
> > -	if (!(gfp_mask & __GFP_NOWARN) && printk_ratelimit())
> > +	if (!(gfp_mask & __GFP_NOWARN) && printk_ratelimit()) {
> >   		pr_warn("vmap allocation for size %lu failed: use vmalloc=<size> to increase size\n",
> >   			size);
> > +		dump_modules_free_space();
> > +	}
> > +
> >   	kmem_cache_free(vmap_area_cachep, va);
> >   	return ERR_PTR(-EBUSY);
> >   }
> 
> Thanks!
> 
> I can spot the same module getting loaded over and over again concurrently
> from user space, only failing after all the allocations when realizing that
> the module is in fact already loaded in add_unformed_module(), failing with
> -EEXIST.
> 
> That looks quite inefficient. Here is how often user space tries to load the
> same module on that system. Note that I print *after* allocating module VMAP
> space.
> 
OK. It explains the problem :) Indeed it is inefficient. Allocating and later
on figuring out that a module is already there looks weird. Furthermore an
attacking from the user space can be organized.


> # dmesg | grep Loading | cut -d" " -f5 | sort | uniq -c
>     896 acpi_cpufreq
>       1 acpi_pad
>       1 acpi_power_meter
>       2 ahci
>       1 cdrom
>       2 compiled-in
>       1 coretemp
>      15 crc32c_intel
>     307 crc32_pclmul
>       1 crc64
>       1 crc64_rocksoft
>       1 crc64_rocksoft_generic
>      12 crct10dif_pclmul
>      16 dca
>       1 dm_log
>       1 dm_mirror
>       1 dm_mod
>       1 dm_region_hash
>       1 drm
>       1 drm_kms_helper
>       1 drm_shmem_helper
>       1 fat
>       1 fb_sys_fops
>      14 fjes
>       1 fuse
>     205 ghash_clmulni_intel
>       1 i2c_algo_bit
>       1 i2c_i801
>       1 i2c_smbus
>       4 i40e
>       4 ib_core
>       1 ib_uverbs
>       4 ice
>     403 intel_cstate
>       1 intel_pch_thermal
>       1 intel_powerclamp
>       1 intel_rapl_common
>       1 intel_rapl_msr
>     399 intel_uncore
>       1 intel_uncore_frequency
>       1 intel_uncore_frequency_common
>      64 ioatdma
>       1 ipmi_devintf
>       1 ipmi_msghandler
>       1 ipmi_si
>       1 ipmi_ssif
>       4 irdma
>     406 irqbypass
>       1 isst_if_common
>     165 isst_if_mbox_msr
>     300 kvm
>     408 kvm_intel
>       1 libahci
>       2 libata
>       1 libcrc32c
>     409 libnvdimm
>       8 Loading
>       1 lpc_ich
>       1 megaraid_sas
>       1 mei
>       1 mei_me
>       1 mgag200
>       1 nfit
>       1 pcspkr
>       1 qrtr
>     405 rapl
>       1 rfkill
>       1 sd_mod
>       2 sg
>     409 skx_edac
>       1 sr_mod
>       1 syscopyarea
>       1 sysfillrect
>       1 sysimgblt
>       1 t10_pi
>       1 uas
>       1 usb_storage
>       1 vfat
>       1 wmi
>       1 x86_pkg_temp_thermal
>       1 xfs
> 
> 
> For each if these loading request, we'll reserve module VMAP space, and free
> it once we realize later that the module was already previously loaded.
> 
> So with a lot of CPUs we might end up trying to load the same module that
> often at the same time that we actually run out of module VMAP space.
> 
> I have a prototype patch that seems to fix this in module loading code.
> 
Good! I am glad the problem can be solved :)

--
Uladzislau Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y0p8BZIiDXLQbde/%40pc636.
