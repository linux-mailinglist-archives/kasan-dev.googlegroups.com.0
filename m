Return-Path: <kasan-dev+bncBDK7LR5URMGRBHEOQGNAMGQE2P6ETJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2456C5F7A9D
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Oct 2022 17:34:53 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id o22-20020a2e90d6000000b0026b8a746a9dsf2058420ljg.6
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Oct 2022 08:34:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665156892; cv=pass;
        d=google.com; s=arc-20160816;
        b=hBgkkzLWxwmvRpgmIzdXN208P2Eu6TiL/kyOkfws3plvDSDcX93KkzTxfu+a4ZmQVI
         W2oJ9BsDFrl2kuiQ9WYJu8qni+vtMJD/RMhLD29WxeHjG5DmIBD8ypX5d/92tek/daWI
         u13p1L+HzLGxz1HkCqC2bmregGYuKB8vxed6F67vQM4AOuELX4Ow8svudOABZjvjZZdf
         +Nsw1nPRgqpN+oH27RNeogfp4IwfZnUz4dZe4H+E1ZCwiJK6yImeYZwExXIrvuViuhOv
         sq8PnCvW1TAJgMPvxFttheZMgBko1fx9g/eXw181ZVjcBF/uzk2oNjT6MNeZF8OH63PG
         XSQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:date:from:sender
         :dkim-signature:dkim-signature;
        bh=rIwiPyAtUo1o9FNojXIw9xzZQNY8CH8g6oyA0iEpzoU=;
        b=JbHs/oaH5lY88jZtWhWM02IaEZfv/2rZ96pzGPgApzM/mxmtaf++1n5TfEOgy05Iho
         F/ROBA261LRW9MG4CkddsE52454q3ZZOTLGjUTTAdrUBkd0VyCYqBvdBJGg5qMsLIETM
         f6DlLa3LqJUnaRcVCDQvH2jqMAh1a+VKR9S57mbcVueJyofylAHtb8rTU174E0Kg5XeM
         DQUaQgmx/9lUfirDujQw2wzpymOKIHapgw8sH0v+CMcuFkGWMixc1eQbWcAJ3MmPS7db
         wnmMNrD7T3ZhJiYPYu1VsGfv/23gTo8I8PEgr0V/NT57E68FbAb2JrayOAy0ong8VuFu
         q2uQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=KfF58vzR;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::235 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=rIwiPyAtUo1o9FNojXIw9xzZQNY8CH8g6oyA0iEpzoU=;
        b=t2jr6TAqlkAJlVR1X6L8x1BnCPQjtWkeAYeVrLuN9GNj930kFMIP33u+P+tH2BLJa5
         qH9NZzbqJ3PUwAi0UTHW2kNCSyUhIrLwdP9Xjp+jjdo0lhpVonZ18U3hL9SNk78U2i0I
         9mviX+H22F8jisnLNDcuxSpYIPGlJ0S2EfG0Sc7wo8M6eX0jGGxoy0pVglpoj1HrpFq7
         Sdd6eZogPZSyAEGeqImoUs7FoK3VJbueXpR9YzaB2BoUHpz3MEU3BbxV/bMRAtGNNk1x
         JN6rrQAHONWqi/Md0LhDbBDpLFD6c/JfcReNri2UWdE1hUYq5hjHVcdvHzT9q2IYeHtI
         o7Ug==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=rIwiPyAtUo1o9FNojXIw9xzZQNY8CH8g6oyA0iEpzoU=;
        b=dEInaW6j1pNibkv/+uVa5Y2Yfokj/uUBUGAOZygHkc/YkNgeU3k76XOqQquSVV3Lge
         qQcmL4H6NSaECHng04mkd4Kj5pOassAt/Yko+rYBLg9D9uBu63we2tLkUvVvZd9LgobX
         mzbOBEZ7DCwHEqwa2WBRiMnr0nl8BQlVyGxn41KZe01w2rZyCqSQEysiNPBaW2Q8/imp
         M67hS3hoklrnoF8d8Ks2CX2GwNTB7h2V8hHnom1WipdWlk/nZQ64xZbjQWzx5sYwc4V7
         OPPz0AQPIQjZVCYtxmAiojMd69OMJT9SSyBO7oD0kWsPPlbm3t0SveJ1Qe4AFlSdb77I
         txHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rIwiPyAtUo1o9FNojXIw9xzZQNY8CH8g6oyA0iEpzoU=;
        b=0HPL94TRRaMjM31WVJOg8fovJ8OFwLs3hzHPf4AA5ToOr+d2Cqg4L+gL6RBl77/lDp
         vbj9nLkqUsQEC5gC5KnbSgd84OZQyGx/oFHLy9MRcr+vOz0+UzaSv538VOSqp3KSaPbq
         X9dGZ2kIvcv/i40s8VoC6tr1naD4u8BKpm/FgKeM362QlIjsRHpcfRF4euCPREXO6+c4
         luT8VZLfUXOq7FNCOK/LkrsMX8v27uHajdvBVcgvbro56Zm5JaQHCRJ9ZKUeZekL0rEM
         kb9w35gCVV29WLXHxFFrW1qyzlmr8bVUx1ygl4RPNznYv7eyHh612CUA2vnU1kC51ymG
         cPBw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1DGErf5y01Pz84u0XFcxYCluk8n1cRBrcYOsgtkHQ5F2DTgopX
	sXWo8qz1qgpaXjuI7Jld9dQ=
X-Google-Smtp-Source: AMsMyM5Izt40lYiKiX0ulxP4VLKJiqZpLC8Gio3/1y2upDHNqB7k+fmJUM9Q2J7m5dt4HxotUw+dNg==
X-Received: by 2002:ac2:5f58:0:b0:4a2:4ac5:5e1a with SMTP id 24-20020ac25f58000000b004a24ac55e1amr2273406lfz.475.1665156892304;
        Fri, 07 Oct 2022 08:34:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3a5:b0:49a:b814:856d with SMTP id
 v5-20020a05651203a500b0049ab814856dls1592853lfp.1.-pod-prod-gmail; Fri, 07
 Oct 2022 08:34:51 -0700 (PDT)
X-Received: by 2002:a19:5503:0:b0:4a2:329d:bc74 with SMTP id n3-20020a195503000000b004a2329dbc74mr2306425lfe.77.1665156891158;
        Fri, 07 Oct 2022 08:34:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665156891; cv=none;
        d=google.com; s=arc-20160816;
        b=oXyvGtPXL7cmIIHFPnf88PSyX6Y7cx0DV/oWby3NH8hBK9Q6C5eqwFTBpnAzKO/MLl
         xXwJGJuEQT7rYzPqfniA6MODuZc52BDpBYSy9QaC0SVcAqf6kEZrDh/vsozxx1mOScYI
         t82CTruftHjRzzzd4udDU8pFi7Y8N36YePKSexdSt1vgR2Mja+GWEutdGgWroOSq7l8z
         n2JPUYes7GzSJ0Yrofouf5AeP1je3QSLwp9QORx4MJUaqztW3FG6EHexJWuTIeDJ/qTq
         OR0Jow8nqr3hMKym8SsEiwH9hlvhH8hSyloZOlxJTeFg6dTkNYPBy7MQbr4w0gxuPkzg
         jGDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:date:from:dkim-signature;
        bh=izkHNBhuBwgvzXtx/73B8psiHiY+7QxtoQMWKis7624=;
        b=pt/tL2mPLb/0RedoIaceDZK9V8/QT6gzc0TZZ5QaS2sNt87keCH7xOe830Q6QrVKzD
         DGm5wDgjzvGa2ZZLfgcqGtYj6QfrJFPykZXpr7S0o20lwskQ8WJ/Xw8ISM8J+mLQ49Bw
         fADodpOnRUAnJ89EhAK1dIKvG89E7u6EKlaXgdNDW0kOxVPTaTgYuZCMKyZC+p/fiK8t
         tAMc21/yNuA+/dR2nxXHOmhFTaN3FjT6WyQFS7sjEsQRNAsjmLxa345qUBk8TuK0H2cA
         2sFwkTU/DpHorRqTEVaLsciwCP6njHCUrMnHQcygUnqeFG3lgQS2/QFncufuIMooQZXD
         fE8w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=KfF58vzR;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::235 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lj1-x235.google.com (mail-lj1-x235.google.com. [2a00:1450:4864:20::235])
        by gmr-mx.google.com with ESMTPS id t12-20020a056512068c00b0048b38f379d7si95725lfe.0.2022.10.07.08.34.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 07 Oct 2022 08:34:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::235 as permitted sender) client-ip=2a00:1450:4864:20::235;
Received: by mail-lj1-x235.google.com with SMTP id bs18so6140737ljb.1
        for <kasan-dev@googlegroups.com>; Fri, 07 Oct 2022 08:34:51 -0700 (PDT)
X-Received: by 2002:a05:651c:222c:b0:26b:dec5:a4f0 with SMTP id y44-20020a05651c222c00b0026bdec5a4f0mr2039980ljq.359.1665156890725;
        Fri, 07 Oct 2022 08:34:50 -0700 (PDT)
Received: from pc636 (host-90-235-26-251.mobileonline.telia.com. [90.235.26.251])
        by smtp.gmail.com with ESMTPSA id f22-20020a2eb5b6000000b0026bf0d71b1esm306749ljn.93.2022.10.07.08.34.49
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 07 Oct 2022 08:34:50 -0700 (PDT)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Fri, 7 Oct 2022 17:34:47 +0200
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
Message-ID: <Y0BHFwbMmcIBaKNZ@pc636>
References: <8aaaeec8-14a1-cdc4-4c77-4878f4979f3e@redhat.com>
 <Yz711WzMS+lG7Zlw@pc636>
 <9ce8a3a3-8305-31a4-a097-3719861c234e@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <9ce8a3a3-8305-31a4-a097-3719861c234e@redhat.com>
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=KfF58vzR;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::235 as
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

> On 06.10.22 17:35, Uladzislau Rezki wrote:
> > > Hi,
> > > 
> > > we're currently hitting a weird vmap issue in debug kernels with KASAN enabled
> > > on fairly large VMs. I reproduced it on v5.19 (did not get the chance to
> > > try 6.0 yet because I don't have access to the machine right now, but
> > > I suspect it persists).
> > > 
> > > It seems to trigger when udev probes a massive amount of devices in parallel
> > > while the system is booting up. Once the system booted, I no longer see any
> > > such issues.
> > > 
> > > 
> > > [  165.818200] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
> > > [  165.836622] vmap allocation for size 315392 failed: use vmalloc=<size> to increase size
> > > [  165.837461] vmap allocation for size 315392 failed: use vmalloc=<size> to increase size
> > > [  165.840573] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
> > > [  165.841059] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
> > > [  165.841428] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
> > > [  165.841819] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
> > > [  165.842123] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
> > > [  165.843359] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
> > > [  165.844894] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
> > > [  165.847028] CPU: 253 PID: 4995 Comm: systemd-udevd Not tainted 5.19.0 #2
> > > [  165.935689] Hardware name: Lenovo ThinkSystem SR950 -[7X12ABC1WW]-/-[7X12ABC1WW]-, BIOS -[PSE130O-1.81]- 05/20/2020
> > > [  165.947343] Call Trace:
> > > [  165.950075]  <TASK>
> > > [  165.952425]  dump_stack_lvl+0x57/0x81
> > > [  165.956532]  warn_alloc.cold+0x95/0x18a
> > > [  165.960836]  ? zone_watermark_ok_safe+0x240/0x240
> > > [  165.966100]  ? slab_free_freelist_hook+0x11d/0x1d0
> > > [  165.971461]  ? __get_vm_area_node+0x2af/0x360
> > > [  165.976341]  ? __get_vm_area_node+0x2af/0x360
> > > [  165.981219]  __vmalloc_node_range+0x291/0x560
> > > [  165.986087]  ? __mutex_unlock_slowpath+0x161/0x5e0
> > > [  165.991447]  ? move_module+0x4c/0x630
> > > [  165.995547]  ? vfree_atomic+0xa0/0xa0
> > > [  165.999647]  ? move_module+0x4c/0x630
> > > [  166.003741]  module_alloc+0xe7/0x170
> > > [  166.007747]  ? move_module+0x4c/0x630
> > > [  166.011840]  move_module+0x4c/0x630
> > > [  166.015751]  layout_and_allocate+0x32c/0x560
> > > [  166.020519]  load_module+0x8e0/0x25c0
> > > 
> > Can it be that we do not have enough "module section" size? I mean the
> > section size, which is MODULES_END - MODULES_VADDR is rather small so
> > some modules are not loaded due to no space.
> > 
> > CONFIG_RANDOMIZE_BASE also creates some offset overhead if enabled on
> > your box. But it looks it is rather negligible.
> 
> Right, I suspected both points -- but was fairly confused why the numbers of
> CPUs would matter.
> 
> What would make sense is that if we're tight on module vmap space, that the
> race I think that could happen with purging only once and then failing could
> become relevant.
> 
> > 
> > Maybe try to increase the module-section size to see if it solves the
> > problem.
> 
> What would be the easiest way to do that?
> 
Sorry for late answer. I was trying to reproduce it on my box. What i
did was trying to load all modules in my system with KASAN_INLINE option:

<snip>
#!/bin/bash

# Exclude test_vmalloc.ko
MODULES_LIST=(`find /lib/modules/$(uname -r) -type f \
	\( -iname "*.ko" -not -iname "test_vmalloc*" \) | awk -F"/" '{print $NF}' | sed 's/.ko//'`)

function moduleExist(){
	MODULE="$1"
	if lsmod | grep "$MODULE" &> /dev/null ; then
		return 0
	else
		return 1
	fi
}

i=0

for module_name in ${MODULES_LIST[@]}; do
	sudo modprobe $module_name

	if moduleExist ${module_name}; then
		((i=i+1))
		echo "Successfully loaded $module_name counter $i"
	fi
done
<snip>

as you wrote it looks like it is not easy to reproduce. So i do not see
any vmap related errors. 

Returning back to the question. I think you could increase the MODULES_END
address and shift the FIXADDR_START little forward. See the dump_pagetables.c
But it might be they are pretty compact and located in the end. So i am not
sure if there is a room there.

Second. It would be good to understand if vmap only fails on allocating for a
module:

<snip>
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index dd6cdb201195..53026fdda224 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -1614,6 +1614,8 @@ static struct vmap_area *alloc_vmap_area(unsigned long size,
        va->va_end = addr + size;
        va->vm = NULL;
 
+       trace_printk("-> alloc %lu size, align: %lu, vstart: %lu, vend: %lu\n", size, align, vstart, vend);
+
        spin_lock(&vmap_area_lock);
<snip>

--
Uladzislau Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y0BHFwbMmcIBaKNZ%40pc636.
