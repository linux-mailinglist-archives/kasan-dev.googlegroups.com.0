Return-Path: <kasan-dev+bncBC7OD3FKWUERBS5D3GXAMGQERF5LSOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C41385E769
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 20:41:01 +0100 (CET)
Received: by mail-oo1-xc3f.google.com with SMTP id 006d021491bc7-59fb255d718sf4119649eaf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 11:41:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708544460; cv=pass;
        d=google.com; s=arc-20160816;
        b=fWgv4dWpbB9/gLWgpvfU7vqfZa5Sa/FlaOW/QrWoc+3u7GUGf9Z3OdIKtHEg47GVnB
         AZ6GQ8KCu+mHkmzZVVk++NkW5eaXm6vj6viosbilcd3JU8ZCB9xt5bQWFHTcok1/St4Z
         AQ5MbWJWU90Odxx1LFV6g+7gkk9VM1ygTyuvLaJyJNGwM8Cgy8PH2HgriS89OFHfS3EP
         MqX/CKiTs5axSgwYAOdjAmbx65TUBpz/GsKOozt/n4ezXaR1VhhQ1JJMPG2zGfWdG5Bc
         YakVesq5BlW6kZ1BS2TTn2JxHTvgX4SyTM+QAWQISRvUnHczwyTeDpMnR+9hG7GX8NgA
         zeVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=VSn6YNk04wfMllQbEcHv+i7LeXm6NU4fMHcfKRXqut4=;
        fh=AUKispa8YoewdDTiDuB3YA90ZYOitr09VHDbK9RIBRo=;
        b=Zd70bmr9M/x+6B4+tWnR1WzJWUpe8Zx9Crrdz5lqTa2rAef6h98Xa2PqKW/T2pVBcN
         Pi9RRuvEotnoWEeHFvYUvdiFYue5/VO650LR0FyzYBt3vWEW/Wyhvzdv/1GdWC8FvHMq
         I02skD9AiinKA4pbxEGkeQzW0LEANVa3MGp3X+RltVKgQ5nI3F5z1n0qd7gSdATOUatR
         eR0qh6uzXHPdSzDz64Eo6ZRnvXo8ZOtWNrEQ05MbyjJcx1c+nYEGmsFVcnjqTvA7/bj4
         uFFnIsbx0eYSIq+kxEgKyDBR6pAox2FhjVHcu/kG+x5M1iCuH69tdfCd72fbLYsMOVx5
         Mwbw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xOVIBJyf;
       spf=pass (google.com: domain of 3ylhwzqykcfsvxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3ylHWZQYKCfsvxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708544460; x=1709149260; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VSn6YNk04wfMllQbEcHv+i7LeXm6NU4fMHcfKRXqut4=;
        b=slQxmt+xW2KoBvLTJkPfx7gSY0NxTECY8kuQ9HLPa1JEM59ZL3hsvNbETAxBU5Hm1R
         bjp14+lhi5XWAedez16iBqots2efy86Zzh8R76TvVag+cogdjjT1YNepQSD1r2auARbk
         mxr4DmnJyDRryQsNNJvYP6AYaww/h0iKOoEYtS0j4jUkW8XqsrfGCK1WF3R6pkM7Vm4p
         HrsE8ZPm2agUjC3vtQUAvycAFFfhgCymMOU2R0BRx4VCgICGxwEY4lr3pK9U1AfV7ZKY
         VD6t0xq2po3FoundXjYt6WnJKdjpNB83RoAIXUGp6kFdylGMOkr0KaTFZqqbMmw26Rfd
         vt3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708544460; x=1709149260;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=VSn6YNk04wfMllQbEcHv+i7LeXm6NU4fMHcfKRXqut4=;
        b=g51RHxGrowOe1DwamErst//KRObKkhrH1Mi9Kr1W9m7tj4DEmSTuKj1fHBG5MyY3ur
         car2ZKXaiPq1fOuZ2OyjcqnJT+w3vJLLHV3hZ6RJfQ2dQU12t1rUB9XPdgUI54dSw88K
         zGAM2NTqMi0B8Yu9NO6FGkJV3+EC/MSgdLaF31ac5nxbnRm+qtGNpXYhK3icLZRRqTip
         CHBLl88DkwGQnuEn+TrSvmClnfBmWQy3DPYjXBfx2wen+VorqOcApGfqsyiWgRuHbBTW
         ms+B3cpdi41EzYwzXcuLXUoDYQEv/vPBogKKb44AcQK8EBTnU0OsJY7Fam3QWL2YGN7K
         djCg==
X-Forwarded-Encrypted: i=2; AJvYcCXVrLO4xUaRXATsqoviv5hRq7rJfA1FvQik29ZcUBpBHztvrZOOLUcunKwGkQ2abkazTXxoMcFx/eStZnvQk30vmPip7GFqmQ==
X-Gm-Message-State: AOJu0YwvIw7GciELoi8U6Kd3PW8mOJxQ1PpSUIfFH84rZ4euRmP+crf7
	6jltLMFyFRybWiqH0+eUT6aS+PAsBAYm5MM4SU89Ur1fTCehOn3Z
X-Google-Smtp-Source: AGHT+IGrR8g4zflg7irONxhIwzkD4iVH9UoD8MBskguamnhu3i9U97UoOQaQFy/XQX32txNmu0xkwQ==
X-Received: by 2002:a4a:d2ce:0:b0:5a0:2a9:5745 with SMTP id j14-20020a4ad2ce000000b005a002a95745mr5042378oos.4.1708544460067;
        Wed, 21 Feb 2024 11:41:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:5703:0:b0:59a:85c:a968 with SMTP id u3-20020a4a5703000000b0059a085ca968ls1077937ooa.2.-pod-prod-04-us;
 Wed, 21 Feb 2024 11:40:59 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWPjvs2wr8jY8Pn7zFDlUMOp50Qupjwb7rpPlToCD2csukSdUqOKA38Mg8nbAjULT5XFSfu4CQCpxap1m/Oun6NYL5LKc6J80994w==
X-Received: by 2002:a9d:5a10:0:b0:6e4:4da8:eb8c with SMTP id v16-20020a9d5a10000000b006e44da8eb8cmr9414904oth.9.1708544459177;
        Wed, 21 Feb 2024 11:40:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708544459; cv=none;
        d=google.com; s=arc-20160816;
        b=vnwekWLWHXllesVkUnj+jjRAzTTy4h7iVNhNaNq57TewJC9eSyVLdCao32Xpz8P41/
         5sIiJ0iR9w7SQt2V4VE3eGNcr1Q0sS9HZ3VSfNLPkH/xSj5vGxZJopXose+X0lzLDbQl
         jhsERu5r2ClWkRI/wTAAF5aza3E4Vn+EmakNid8TY5uYD5pqCCcX1G8sl0ltEZozPmmi
         iop2M5LEGxNtEp/7Ei2WmTuNYuNc1HUPblZR6mhiL2upXi9YCv1SPFgJnITpjwEra7kN
         gJhNfhPU7PvpxyrvC9bC3QBbsRJAgDIx7wETLHGLulF66GpABljIKdGlEnqhbg+VwzQk
         zjeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:dkim-signature;
        bh=YsTKwVJ6O4OlJiNRRNjRyUU9LCYieAfH/reETwxdtW4=;
        fh=9YmTbHQiwee8LtyZa1eajHFa4DgNyx87TaPeyXDYWGM=;
        b=e7YyI2z5S0yYwPFkkaWu4+SOdbLrt2eYNnrByJp99wTnXQ5JmuFytD7Z6eS7gVMG18
         cx3zrUeqmGtlt9aPHJT+K8uyIdCSRA6BpX3/T2L9DkhpMYkf3HxLSH2+fFC60pZ2hhrF
         c+q3XhgD1Jf22vHei5uImcZBgAJZ82UPMNtfEjSIqXsQPNX7dfP0mVXf2W5HpNNNvoEl
         Xm3/M0cTBIasTEMOKyz6hd+k6Eb1aejDscXKmDsdoVSKM615wSkt/ZT6cHMB2dU4bUL7
         84nnjUZUdSvYjLqq+wutR3/5NKaR8naUm6KxlQFUvZ8VR0wqbjo+8H2if89LbpM3cpVU
         Nuyw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xOVIBJyf;
       spf=pass (google.com: domain of 3ylhwzqykcfsvxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3ylHWZQYKCfsvxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id cr23-20020a056830671700b006e458661192si422412otb.5.2024.02.21.11.40.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 11:40:59 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ylhwzqykcfsvxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-dcf22e5b70bso551373276.1
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 11:40:59 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV21SJmaC1xChhJXjwDgbRaEGLP1yyFA1wtFZmgMwoVdICCl6o9FgUQ262Lvm3i2hW/is1nyG3DYmIQ2hfEVjB83o1W9pfr4eNXTQ==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:953b:9a4e:1e10:3f07])
 (user=surenb job=sendgmr) by 2002:a05:6902:154f:b0:dc6:d890:1a97 with SMTP id
 r15-20020a056902154f00b00dc6d8901a97mr17436ybu.9.1708544458467; Wed, 21 Feb
 2024 11:40:58 -0800 (PST)
Date: Wed, 21 Feb 2024 11:40:14 -0800
In-Reply-To: <20240221194052.927623-1-surenb@google.com>
Mime-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.rc0.258.g7320e95886-goog
Message-ID: <20240221194052.927623-2-surenb@google.com>
Subject: [PATCH v4 01/36] fix missing vmalloc.h includes
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
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
	minchan@google.com, kaleshsingh@google.com, surenb@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=xOVIBJyf;       spf=pass
 (google.com: domain of 3ylhwzqykcfsvxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3ylHWZQYKCfsvxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

From: Kent Overstreet <kent.overstreet@linux.dev>

The next patch drops vmalloc.h from a system header in order to fix
a circular dependency; this adds it to all the files that were pulling
it in implicitly.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 arch/alpha/lib/checksum.c                                | 1 +
 arch/alpha/lib/fpreg.c                                   | 1 +
 arch/alpha/lib/memcpy.c                                  | 1 +
 arch/arm/kernel/irq.c                                    | 1 +
 arch/arm/kernel/traps.c                                  | 1 +
 arch/arm64/kernel/efi.c                                  | 1 +
 arch/loongarch/include/asm/kfence.h                      | 1 +
 arch/powerpc/kernel/iommu.c                              | 1 +
 arch/powerpc/mm/mem.c                                    | 1 +
 arch/riscv/kernel/elf_kexec.c                            | 1 +
 arch/riscv/kernel/probes/kprobes.c                       | 1 +
 arch/s390/kernel/cert_store.c                            | 1 +
 arch/s390/kernel/ipl.c                                   | 1 +
 arch/x86/include/asm/io.h                                | 1 +
 arch/x86/kernel/cpu/sgx/main.c                           | 1 +
 arch/x86/kernel/irq_64.c                                 | 1 +
 arch/x86/mm/fault.c                                      | 1 +
 drivers/accel/ivpu/ivpu_mmu_context.c                    | 1 +
 drivers/gpu/drm/gma500/mmu.c                             | 1 +
 drivers/gpu/drm/i915/gem/i915_gem_pages.c                | 1 +
 drivers/gpu/drm/i915/gem/selftests/mock_dmabuf.c         | 1 +
 drivers/gpu/drm/i915/gt/shmem_utils.c                    | 1 +
 drivers/gpu/drm/i915/gvt/firmware.c                      | 1 +
 drivers/gpu/drm/i915/gvt/gtt.c                           | 1 +
 drivers/gpu/drm/i915/gvt/handlers.c                      | 1 +
 drivers/gpu/drm/i915/gvt/mmio.c                          | 1 +
 drivers/gpu/drm/i915/gvt/vgpu.c                          | 1 +
 drivers/gpu/drm/i915/intel_gvt.c                         | 1 +
 drivers/gpu/drm/imagination/pvr_vm_mips.c                | 1 +
 drivers/gpu/drm/mediatek/mtk_drm_gem.c                   | 1 +
 drivers/gpu/drm/omapdrm/omap_gem.c                       | 1 +
 drivers/gpu/drm/v3d/v3d_bo.c                             | 1 +
 drivers/gpu/drm/vmwgfx/vmwgfx_binding.c                  | 1 +
 drivers/gpu/drm/vmwgfx/vmwgfx_cmd.c                      | 1 +
 drivers/gpu/drm/vmwgfx/vmwgfx_devcaps.c                  | 1 +
 drivers/gpu/drm/vmwgfx/vmwgfx_drv.c                      | 1 +
 drivers/gpu/drm/vmwgfx/vmwgfx_execbuf.c                  | 1 +
 drivers/gpu/drm/vmwgfx/vmwgfx_ioctl.c                    | 1 +
 drivers/gpu/drm/xen/xen_drm_front_gem.c                  | 1 +
 drivers/hwtracing/coresight/coresight-trbe.c             | 1 +
 drivers/net/ethernet/marvell/octeon_ep/octep_pfvf_mbox.c | 1 +
 drivers/net/ethernet/microsoft/mana/hw_channel.c         | 1 +
 drivers/platform/x86/uv_sysfs.c                          | 1 +
 drivers/scsi/mpi3mr/mpi3mr_transport.c                   | 2 ++
 drivers/vfio/pci/pds/dirty.c                             | 1 +
 drivers/virt/acrn/mm.c                                   | 1 +
 drivers/virtio/virtio_mem.c                              | 1 +
 include/linux/pds/pds_common.h                           | 2 ++
 include/rdma/rdmavt_qp.h                                 | 1 +
 mm/debug_vm_pgtable.c                                    | 1 +
 sound/pci/hda/cs35l41_hda.c                              | 1 +
 51 files changed, 53 insertions(+)

diff --git a/arch/alpha/lib/checksum.c b/arch/alpha/lib/checksum.c
index 3f35c3ed6948..c29b98ef9c82 100644
--- a/arch/alpha/lib/checksum.c
+++ b/arch/alpha/lib/checksum.c
@@ -14,6 +14,7 @@
 #include <linux/string.h>
=20
 #include <asm/byteorder.h>
+#include <asm/checksum.h>
=20
 static inline unsigned short from64to16(unsigned long x)
 {
diff --git a/arch/alpha/lib/fpreg.c b/arch/alpha/lib/fpreg.c
index 7c08b225261c..3d32165043f8 100644
--- a/arch/alpha/lib/fpreg.c
+++ b/arch/alpha/lib/fpreg.c
@@ -8,6 +8,7 @@
 #include <linux/compiler.h>
 #include <linux/export.h>
 #include <linux/preempt.h>
+#include <asm/fpu.h>
 #include <asm/thread_info.h>
=20
 #if defined(CONFIG_ALPHA_EV6) || defined(CONFIG_ALPHA_EV67)
diff --git a/arch/alpha/lib/memcpy.c b/arch/alpha/lib/memcpy.c
index cbac3dc6d963..0e536a1a39ff 100644
--- a/arch/alpha/lib/memcpy.c
+++ b/arch/alpha/lib/memcpy.c
@@ -18,6 +18,7 @@
=20
 #include <linux/types.h>
 #include <linux/export.h>
+#include <linux/string.h>
=20
 /*
  * This should be done in one go with ldq_u*2/mask/stq_u. Do it
diff --git a/arch/arm/kernel/irq.c b/arch/arm/kernel/irq.c
index fe28fc1f759d..dab42d066d06 100644
--- a/arch/arm/kernel/irq.c
+++ b/arch/arm/kernel/irq.c
@@ -32,6 +32,7 @@
 #include <linux/kallsyms.h>
 #include <linux/proc_fs.h>
 #include <linux/export.h>
+#include <linux/vmalloc.h>
=20
 #include <asm/hardware/cache-l2x0.h>
 #include <asm/hardware/cache-uniphier.h>
diff --git a/arch/arm/kernel/traps.c b/arch/arm/kernel/traps.c
index 3bad79db5d6e..27addbf0f98c 100644
--- a/arch/arm/kernel/traps.c
+++ b/arch/arm/kernel/traps.c
@@ -26,6 +26,7 @@
 #include <linux/sched/debug.h>
 #include <linux/sched/task_stack.h>
 #include <linux/irq.h>
+#include <linux/vmalloc.h>
=20
 #include <linux/atomic.h>
 #include <asm/cacheflush.h>
diff --git a/arch/arm64/kernel/efi.c b/arch/arm64/kernel/efi.c
index 0228001347be..a0dc6b88b11b 100644
--- a/arch/arm64/kernel/efi.c
+++ b/arch/arm64/kernel/efi.c
@@ -10,6 +10,7 @@
 #include <linux/efi.h>
 #include <linux/init.h>
 #include <linux/screen_info.h>
+#include <linux/vmalloc.h>
=20
 #include <asm/efi.h>
 #include <asm/stacktrace.h>
diff --git a/arch/loongarch/include/asm/kfence.h b/arch/loongarch/include/a=
sm/kfence.h
index 6c82aea1c993..54062656dc7b 100644
--- a/arch/loongarch/include/asm/kfence.h
+++ b/arch/loongarch/include/asm/kfence.h
@@ -10,6 +10,7 @@
 #define _ASM_LOONGARCH_KFENCE_H
=20
 #include <linux/kfence.h>
+#include <linux/vmalloc.h>
 #include <asm/pgtable.h>
 #include <asm/tlb.h>
=20
diff --git a/arch/powerpc/kernel/iommu.c b/arch/powerpc/kernel/iommu.c
index a9bebfd56b3b..25782d361884 100644
--- a/arch/powerpc/kernel/iommu.c
+++ b/arch/powerpc/kernel/iommu.c
@@ -26,6 +26,7 @@
 #include <linux/iommu.h>
 #include <linux/sched.h>
 #include <linux/debugfs.h>
+#include <linux/vmalloc.h>
 #include <asm/io.h>
 #include <asm/iommu.h>
 #include <asm/pci-bridge.h>
diff --git a/arch/powerpc/mm/mem.c b/arch/powerpc/mm/mem.c
index 3a440004b97d..a197d4c2244b 100644
--- a/arch/powerpc/mm/mem.c
+++ b/arch/powerpc/mm/mem.c
@@ -16,6 +16,7 @@
 #include <linux/highmem.h>
 #include <linux/suspend.h>
 #include <linux/dma-direct.h>
+#include <linux/vmalloc.h>
=20
 #include <asm/swiotlb.h>
 #include <asm/machdep.h>
diff --git a/arch/riscv/kernel/elf_kexec.c b/arch/riscv/kernel/elf_kexec.c
index 5bd1ec3341fe..92b1e16f99c4 100644
--- a/arch/riscv/kernel/elf_kexec.c
+++ b/arch/riscv/kernel/elf_kexec.c
@@ -19,6 +19,7 @@
 #include <linux/libfdt.h>
 #include <linux/types.h>
 #include <linux/memblock.h>
+#include <linux/vmalloc.h>
 #include <asm/setup.h>
=20
 int arch_kimage_file_post_load_cleanup(struct kimage *image)
diff --git a/arch/riscv/kernel/probes/kprobes.c b/arch/riscv/kernel/probes/=
kprobes.c
index 2f08c14a933d..71a8b8945b26 100644
--- a/arch/riscv/kernel/probes/kprobes.c
+++ b/arch/riscv/kernel/probes/kprobes.c
@@ -6,6 +6,7 @@
 #include <linux/extable.h>
 #include <linux/slab.h>
 #include <linux/stop_machine.h>
+#include <linux/vmalloc.h>
 #include <asm/ptrace.h>
 #include <linux/uaccess.h>
 #include <asm/sections.h>
diff --git a/arch/s390/kernel/cert_store.c b/arch/s390/kernel/cert_store.c
index 554447768bdd..bf983513dd33 100644
--- a/arch/s390/kernel/cert_store.c
+++ b/arch/s390/kernel/cert_store.c
@@ -21,6 +21,7 @@
 #include <linux/seq_file.h>
 #include <linux/slab.h>
 #include <linux/sysfs.h>
+#include <linux/vmalloc.h>
 #include <crypto/sha2.h>
 #include <keys/user-type.h>
 #include <asm/debug.h>
diff --git a/arch/s390/kernel/ipl.c b/arch/s390/kernel/ipl.c
index ba75f6bee774..0854a8450a6e 100644
--- a/arch/s390/kernel/ipl.c
+++ b/arch/s390/kernel/ipl.c
@@ -20,6 +20,7 @@
 #include <linux/gfp.h>
 #include <linux/crash_dump.h>
 #include <linux/debug_locks.h>
+#include <linux/vmalloc.h>
 #include <asm/asm-extable.h>
 #include <asm/diag.h>
 #include <asm/ipl.h>
diff --git a/arch/x86/include/asm/io.h b/arch/x86/include/asm/io.h
index 3814a9263d64..c6b799d28126 100644
--- a/arch/x86/include/asm/io.h
+++ b/arch/x86/include/asm/io.h
@@ -42,6 +42,7 @@
 #include <asm/early_ioremap.h>
 #include <asm/pgtable_types.h>
 #include <asm/shared/io.h>
+#include <asm/special_insns.h>
=20
 #define build_mmio_read(name, size, type, reg, barrier) \
 static inline type name(const volatile void __iomem *addr) \
diff --git a/arch/x86/kernel/cpu/sgx/main.c b/arch/x86/kernel/cpu/sgx/main.=
c
index 166692f2d501..27892e57c4ef 100644
--- a/arch/x86/kernel/cpu/sgx/main.c
+++ b/arch/x86/kernel/cpu/sgx/main.c
@@ -13,6 +13,7 @@
 #include <linux/sched/signal.h>
 #include <linux/slab.h>
 #include <linux/sysfs.h>
+#include <linux/vmalloc.h>
 #include <asm/sgx.h>
 #include "driver.h"
 #include "encl.h"
diff --git a/arch/x86/kernel/irq_64.c b/arch/x86/kernel/irq_64.c
index fe0c859873d1..ade0043ce56e 100644
--- a/arch/x86/kernel/irq_64.c
+++ b/arch/x86/kernel/irq_64.c
@@ -18,6 +18,7 @@
 #include <linux/uaccess.h>
 #include <linux/smp.h>
 #include <linux/sched/task_stack.h>
+#include <linux/vmalloc.h>
=20
 #include <asm/cpu_entry_area.h>
 #include <asm/softirq_stack.h>
diff --git a/arch/x86/mm/fault.c b/arch/x86/mm/fault.c
index 679b09cfe241..af223e57aa63 100644
--- a/arch/x86/mm/fault.c
+++ b/arch/x86/mm/fault.c
@@ -20,6 +20,7 @@
 #include <linux/efi.h>			/* efi_crash_gracefully_on_page_fault()*/
 #include <linux/mm_types.h>
 #include <linux/mm.h>			/* find_and_lock_vma() */
+#include <linux/vmalloc.h>
=20
 #include <asm/cpufeature.h>		/* boot_cpu_has, ...		*/
 #include <asm/traps.h>			/* dotraplinkage, ...		*/
diff --git a/drivers/accel/ivpu/ivpu_mmu_context.c b/drivers/accel/ivpu/ivp=
u_mmu_context.c
index fe6161299236..128aef8e5a19 100644
--- a/drivers/accel/ivpu/ivpu_mmu_context.c
+++ b/drivers/accel/ivpu/ivpu_mmu_context.c
@@ -6,6 +6,7 @@
 #include <linux/bitfield.h>
 #include <linux/highmem.h>
 #include <linux/set_memory.h>
+#include <linux/vmalloc.h>
=20
 #include <drm/drm_cache.h>
=20
diff --git a/drivers/gpu/drm/gma500/mmu.c b/drivers/gpu/drm/gma500/mmu.c
index a70b01ccdf70..4d78b33eaa82 100644
--- a/drivers/gpu/drm/gma500/mmu.c
+++ b/drivers/gpu/drm/gma500/mmu.c
@@ -5,6 +5,7 @@
  *************************************************************************=
*/
=20
 #include <linux/highmem.h>
+#include <linux/vmalloc.h>
=20
 #include "mmu.h"
 #include "psb_drv.h"
diff --git a/drivers/gpu/drm/i915/gem/i915_gem_pages.c b/drivers/gpu/drm/i9=
15/gem/i915_gem_pages.c
index 0ba955611dfb..8780aa243105 100644
--- a/drivers/gpu/drm/i915/gem/i915_gem_pages.c
+++ b/drivers/gpu/drm/i915/gem/i915_gem_pages.c
@@ -5,6 +5,7 @@
  */
=20
 #include <drm/drm_cache.h>
+#include <linux/vmalloc.h>
=20
 #include "gt/intel_gt.h"
 #include "gt/intel_tlb.h"
diff --git a/drivers/gpu/drm/i915/gem/selftests/mock_dmabuf.c b/drivers/gpu=
/drm/i915/gem/selftests/mock_dmabuf.c
index b2a5882b8f81..075657018739 100644
--- a/drivers/gpu/drm/i915/gem/selftests/mock_dmabuf.c
+++ b/drivers/gpu/drm/i915/gem/selftests/mock_dmabuf.c
@@ -4,6 +4,7 @@
  * Copyright =C2=A9 2016 Intel Corporation
  */
=20
+#include <linux/vmalloc.h>
 #include "mock_dmabuf.h"
=20
 static struct sg_table *mock_map_dma_buf(struct dma_buf_attachment *attach=
ment,
diff --git a/drivers/gpu/drm/i915/gt/shmem_utils.c b/drivers/gpu/drm/i915/g=
t/shmem_utils.c
index bccc3a1200bc..1fb6ff77fd89 100644
--- a/drivers/gpu/drm/i915/gt/shmem_utils.c
+++ b/drivers/gpu/drm/i915/gt/shmem_utils.c
@@ -7,6 +7,7 @@
 #include <linux/mm.h>
 #include <linux/pagemap.h>
 #include <linux/shmem_fs.h>
+#include <linux/vmalloc.h>
=20
 #include "i915_drv.h"
 #include "gem/i915_gem_object.h"
diff --git a/drivers/gpu/drm/i915/gvt/firmware.c b/drivers/gpu/drm/i915/gvt=
/firmware.c
index 4dd52ac2043e..d800d267f0e9 100644
--- a/drivers/gpu/drm/i915/gvt/firmware.c
+++ b/drivers/gpu/drm/i915/gvt/firmware.c
@@ -30,6 +30,7 @@
=20
 #include <linux/firmware.h>
 #include <linux/crc32.h>
+#include <linux/vmalloc.h>
=20
 #include "i915_drv.h"
 #include "gvt.h"
diff --git a/drivers/gpu/drm/i915/gvt/gtt.c b/drivers/gpu/drm/i915/gvt/gtt.=
c
index 094fca9b0e73..58cca4906f41 100644
--- a/drivers/gpu/drm/i915/gvt/gtt.c
+++ b/drivers/gpu/drm/i915/gvt/gtt.c
@@ -39,6 +39,7 @@
 #include "trace.h"
=20
 #include "gt/intel_gt_regs.h"
+#include <linux/vmalloc.h>
=20
 #if defined(VERBOSE_DEBUG)
 #define gvt_vdbg_mm(fmt, args...) gvt_dbg_mm(fmt, ##args)
diff --git a/drivers/gpu/drm/i915/gvt/handlers.c b/drivers/gpu/drm/i915/gvt=
/handlers.c
index efcb00472be2..ea9c30092767 100644
--- a/drivers/gpu/drm/i915/gvt/handlers.c
+++ b/drivers/gpu/drm/i915/gvt/handlers.c
@@ -52,6 +52,7 @@
 #include "display/skl_watermark_regs.h"
 #include "display/vlv_dsi_pll_regs.h"
 #include "gt/intel_gt_regs.h"
+#include <linux/vmalloc.h>
=20
 /* XXX FIXME i915 has changed PP_XXX definition */
 #define PCH_PP_STATUS  _MMIO(0xc7200)
diff --git a/drivers/gpu/drm/i915/gvt/mmio.c b/drivers/gpu/drm/i915/gvt/mmi=
o.c
index 5b5def6ddef7..780762f28aa4 100644
--- a/drivers/gpu/drm/i915/gvt/mmio.c
+++ b/drivers/gpu/drm/i915/gvt/mmio.c
@@ -33,6 +33,7 @@
  *
  */
=20
+#include <linux/vmalloc.h>
 #include "i915_drv.h"
 #include "i915_reg.h"
 #include "gvt.h"
diff --git a/drivers/gpu/drm/i915/gvt/vgpu.c b/drivers/gpu/drm/i915/gvt/vgp=
u.c
index 08ad1bd651f1..63c751ca4119 100644
--- a/drivers/gpu/drm/i915/gvt/vgpu.c
+++ b/drivers/gpu/drm/i915/gvt/vgpu.c
@@ -34,6 +34,7 @@
 #include "i915_drv.h"
 #include "gvt.h"
 #include "i915_pvinfo.h"
+#include <linux/vmalloc.h>
=20
 void populate_pvinfo_page(struct intel_vgpu *vgpu)
 {
diff --git a/drivers/gpu/drm/i915/intel_gvt.c b/drivers/gpu/drm/i915/intel_=
gvt.c
index 9b6d87c8b583..5a01d60e5186 100644
--- a/drivers/gpu/drm/i915/intel_gvt.c
+++ b/drivers/gpu/drm/i915/intel_gvt.c
@@ -28,6 +28,7 @@
 #include "gt/intel_context.h"
 #include "gt/intel_ring.h"
 #include "gt/shmem_utils.h"
+#include <linux/vmalloc.h>
=20
 /**
  * DOC: Intel GVT-g host support
diff --git a/drivers/gpu/drm/imagination/pvr_vm_mips.c b/drivers/gpu/drm/im=
agination/pvr_vm_mips.c
index b7fef3c797e6..6563dcde109c 100644
--- a/drivers/gpu/drm/imagination/pvr_vm_mips.c
+++ b/drivers/gpu/drm/imagination/pvr_vm_mips.c
@@ -14,6 +14,7 @@
 #include <linux/err.h>
 #include <linux/slab.h>
 #include <linux/types.h>
+#include <linux/vmalloc.h>
=20
 /**
  * pvr_vm_mips_init() - Initialise MIPS FW pagetable
diff --git a/drivers/gpu/drm/mediatek/mtk_drm_gem.c b/drivers/gpu/drm/media=
tek/mtk_drm_gem.c
index 4f2e3feabc0f..3e519869b632 100644
--- a/drivers/gpu/drm/mediatek/mtk_drm_gem.c
+++ b/drivers/gpu/drm/mediatek/mtk_drm_gem.c
@@ -4,6 +4,7 @@
  */
=20
 #include <linux/dma-buf.h>
+#include <linux/vmalloc.h>
=20
 #include <drm/drm.h>
 #include <drm/drm_device.h>
diff --git a/drivers/gpu/drm/omapdrm/omap_gem.c b/drivers/gpu/drm/omapdrm/o=
map_gem.c
index 3421e8389222..9ea0c64c26b5 100644
--- a/drivers/gpu/drm/omapdrm/omap_gem.c
+++ b/drivers/gpu/drm/omapdrm/omap_gem.c
@@ -9,6 +9,7 @@
 #include <linux/shmem_fs.h>
 #include <linux/spinlock.h>
 #include <linux/pfn_t.h>
+#include <linux/vmalloc.h>
=20
 #include <drm/drm_prime.h>
 #include <drm/drm_vma_manager.h>
diff --git a/drivers/gpu/drm/v3d/v3d_bo.c b/drivers/gpu/drm/v3d/v3d_bo.c
index 1bdfac8beafd..bd078852cd60 100644
--- a/drivers/gpu/drm/v3d/v3d_bo.c
+++ b/drivers/gpu/drm/v3d/v3d_bo.c
@@ -21,6 +21,7 @@
=20
 #include <linux/dma-buf.h>
 #include <linux/pfn_t.h>
+#include <linux/vmalloc.h>
=20
 #include "v3d_drv.h"
 #include "uapi/drm/v3d_drm.h"
diff --git a/drivers/gpu/drm/vmwgfx/vmwgfx_binding.c b/drivers/gpu/drm/vmwg=
fx/vmwgfx_binding.c
index ae2de914eb89..2731f6ded1c2 100644
--- a/drivers/gpu/drm/vmwgfx/vmwgfx_binding.c
+++ b/drivers/gpu/drm/vmwgfx/vmwgfx_binding.c
@@ -54,6 +54,7 @@
 #include "vmwgfx_drv.h"
 #include "vmwgfx_binding.h"
 #include "device_include/svga3d_reg.h"
+#include <linux/vmalloc.h>
=20
 #define VMW_BINDING_RT_BIT     0
 #define VMW_BINDING_PS_BIT     1
diff --git a/drivers/gpu/drm/vmwgfx/vmwgfx_cmd.c b/drivers/gpu/drm/vmwgfx/v=
mwgfx_cmd.c
index 195ff8792e5a..dd4ca6a9c690 100644
--- a/drivers/gpu/drm/vmwgfx/vmwgfx_cmd.c
+++ b/drivers/gpu/drm/vmwgfx/vmwgfx_cmd.c
@@ -31,6 +31,7 @@
 #include <drm/ttm/ttm_placement.h>
=20
 #include <linux/sched/signal.h>
+#include <linux/vmalloc.h>
=20
 bool vmw_supports_3d(struct vmw_private *dev_priv)
 {
diff --git a/drivers/gpu/drm/vmwgfx/vmwgfx_devcaps.c b/drivers/gpu/drm/vmwg=
fx/vmwgfx_devcaps.c
index 829df395c2ed..6e6beff9e262 100644
--- a/drivers/gpu/drm/vmwgfx/vmwgfx_devcaps.c
+++ b/drivers/gpu/drm/vmwgfx/vmwgfx_devcaps.c
@@ -25,6 +25,7 @@
  *
  *************************************************************************=
*/
=20
+#include <linux/vmalloc.h>
 #include "vmwgfx_devcaps.h"
=20
 #include "vmwgfx_drv.h"
diff --git a/drivers/gpu/drm/vmwgfx/vmwgfx_drv.c b/drivers/gpu/drm/vmwgfx/v=
mwgfx_drv.c
index d3e308fdfd5b..7a451410ad77 100644
--- a/drivers/gpu/drm/vmwgfx/vmwgfx_drv.c
+++ b/drivers/gpu/drm/vmwgfx/vmwgfx_drv.c
@@ -53,6 +53,7 @@
 #include <linux/module.h>
 #include <linux/pci.h>
 #include <linux/version.h>
+#include <linux/vmalloc.h>
=20
 #define VMWGFX_DRIVER_DESC "Linux drm driver for VMware graphics devices"
=20
diff --git a/drivers/gpu/drm/vmwgfx/vmwgfx_execbuf.c b/drivers/gpu/drm/vmwg=
fx/vmwgfx_execbuf.c
index 36987ef3fc30..4ce22843015e 100644
--- a/drivers/gpu/drm/vmwgfx/vmwgfx_execbuf.c
+++ b/drivers/gpu/drm/vmwgfx/vmwgfx_execbuf.c
@@ -35,6 +35,7 @@
=20
 #include <linux/sync_file.h>
 #include <linux/hashtable.h>
+#include <linux/vmalloc.h>
=20
 /*
  * Helper macro to get dx_ctx_node if available otherwise print an error
diff --git a/drivers/gpu/drm/vmwgfx/vmwgfx_ioctl.c b/drivers/gpu/drm/vmwgfx=
/vmwgfx_ioctl.c
index a1da5678c731..835d1eed8dd9 100644
--- a/drivers/gpu/drm/vmwgfx/vmwgfx_ioctl.c
+++ b/drivers/gpu/drm/vmwgfx/vmwgfx_ioctl.c
@@ -31,6 +31,7 @@
=20
 #include <drm/vmwgfx_drm.h>
 #include <linux/pci.h>
+#include <linux/vmalloc.h>
=20
 int vmw_getparam_ioctl(struct drm_device *dev, void *data,
 		       struct drm_file *file_priv)
diff --git a/drivers/gpu/drm/xen/xen_drm_front_gem.c b/drivers/gpu/drm/xen/=
xen_drm_front_gem.c
index 3ad2b4cfd1f0..63112ed975c4 100644
--- a/drivers/gpu/drm/xen/xen_drm_front_gem.c
+++ b/drivers/gpu/drm/xen/xen_drm_front_gem.c
@@ -11,6 +11,7 @@
 #include <linux/dma-buf.h>
 #include <linux/scatterlist.h>
 #include <linux/shmem_fs.h>
+#include <linux/vmalloc.h>
=20
 #include <drm/drm_gem.h>
 #include <drm/drm_prime.h>
diff --git a/drivers/hwtracing/coresight/coresight-trbe.c b/drivers/hwtraci=
ng/coresight/coresight-trbe.c
index 6136776482e6..96a32b213669 100644
--- a/drivers/hwtracing/coresight/coresight-trbe.c
+++ b/drivers/hwtracing/coresight/coresight-trbe.c
@@ -17,6 +17,7 @@
=20
 #include <asm/barrier.h>
 #include <asm/cpufeature.h>
+#include <linux/vmalloc.h>
=20
 #include "coresight-self-hosted-trace.h"
 #include "coresight-trbe.h"
diff --git a/drivers/net/ethernet/marvell/octeon_ep/octep_pfvf_mbox.c b/dri=
vers/net/ethernet/marvell/octeon_ep/octep_pfvf_mbox.c
index 2e2c3be8a0b4..e6eb98d70f3c 100644
--- a/drivers/net/ethernet/marvell/octeon_ep/octep_pfvf_mbox.c
+++ b/drivers/net/ethernet/marvell/octeon_ep/octep_pfvf_mbox.c
@@ -15,6 +15,7 @@
 #include <linux/io.h>
 #include <linux/pci.h>
 #include <linux/etherdevice.h>
+#include <linux/vmalloc.h>
=20
 #include "octep_config.h"
 #include "octep_main.h"
diff --git a/drivers/net/ethernet/microsoft/mana/hw_channel.c b/drivers/net=
/ethernet/microsoft/mana/hw_channel.c
index 2729a2c5acf9..11021c34e47e 100644
--- a/drivers/net/ethernet/microsoft/mana/hw_channel.c
+++ b/drivers/net/ethernet/microsoft/mana/hw_channel.c
@@ -3,6 +3,7 @@
=20
 #include <net/mana/gdma.h>
 #include <net/mana/hw_channel.h>
+#include <linux/vmalloc.h>
=20
 static int mana_hwc_get_msg_index(struct hw_channel_context *hwc, u16 *msg=
_id)
 {
diff --git a/drivers/platform/x86/uv_sysfs.c b/drivers/platform/x86/uv_sysf=
s.c
index 38d1b692d3c0..40e010877189 100644
--- a/drivers/platform/x86/uv_sysfs.c
+++ b/drivers/platform/x86/uv_sysfs.c
@@ -11,6 +11,7 @@
 #include <linux/device.h>
 #include <linux/slab.h>
 #include <linux/kobject.h>
+#include <linux/vmalloc.h>
 #include <asm/uv/bios.h>
 #include <asm/uv/uv.h>
 #include <asm/uv/uv_hub.h>
diff --git a/drivers/scsi/mpi3mr/mpi3mr_transport.c b/drivers/scsi/mpi3mr/m=
pi3mr_transport.c
index c0c8ab586957..408a4023406b 100644
--- a/drivers/scsi/mpi3mr/mpi3mr_transport.c
+++ b/drivers/scsi/mpi3mr/mpi3mr_transport.c
@@ -7,6 +7,8 @@
  *
  */
=20
+#include <linux/vmalloc.h>
+
 #include "mpi3mr.h"
=20
 /**
diff --git a/drivers/vfio/pci/pds/dirty.c b/drivers/vfio/pci/pds/dirty.c
index 8ddf4346fcd5..0a161becd646 100644
--- a/drivers/vfio/pci/pds/dirty.c
+++ b/drivers/vfio/pci/pds/dirty.c
@@ -3,6 +3,7 @@
=20
 #include <linux/interval_tree.h>
 #include <linux/vfio.h>
+#include <linux/vmalloc.h>
=20
 #include <linux/pds/pds_common.h>
 #include <linux/pds/pds_core_if.h>
diff --git a/drivers/virt/acrn/mm.c b/drivers/virt/acrn/mm.c
index fa5d9ca6be57..c088ee1f1180 100644
--- a/drivers/virt/acrn/mm.c
+++ b/drivers/virt/acrn/mm.c
@@ -12,6 +12,7 @@
 #include <linux/io.h>
 #include <linux/mm.h>
 #include <linux/slab.h>
+#include <linux/vmalloc.h>
=20
 #include "acrn_drv.h"
=20
diff --git a/drivers/virtio/virtio_mem.c b/drivers/virtio/virtio_mem.c
index 8e3223294442..e8355f55a8f7 100644
--- a/drivers/virtio/virtio_mem.c
+++ b/drivers/virtio/virtio_mem.c
@@ -21,6 +21,7 @@
 #include <linux/bitmap.h>
 #include <linux/lockdep.h>
 #include <linux/log2.h>
+#include <linux/vmalloc.h>
=20
 #include <acpi/acpi_numa.h>
=20
diff --git a/include/linux/pds/pds_common.h b/include/linux/pds/pds_common.=
h
index 30581e2e04cc..5802e1deef24 100644
--- a/include/linux/pds/pds_common.h
+++ b/include/linux/pds/pds_common.h
@@ -4,6 +4,8 @@
 #ifndef _PDS_COMMON_H_
 #define _PDS_COMMON_H_
=20
+#include <linux/notifier.h>
+
 #define PDS_CORE_DRV_NAME			"pds_core"
=20
 /* the device's internal addressing uses up to 52 bits */
diff --git a/include/rdma/rdmavt_qp.h b/include/rdma/rdmavt_qp.h
index 2e58d5e6ac0e..d67892944193 100644
--- a/include/rdma/rdmavt_qp.h
+++ b/include/rdma/rdmavt_qp.h
@@ -11,6 +11,7 @@
 #include <rdma/ib_verbs.h>
 #include <rdma/rdmavt_cq.h>
 #include <rdma/rvt-abi.h>
+#include <linux/vmalloc.h>
 /*
  * Atomic bit definitions for r_aflags.
  */
diff --git a/mm/debug_vm_pgtable.c b/mm/debug_vm_pgtable.c
index 5662e29fe253..d711246929aa 100644
--- a/mm/debug_vm_pgtable.c
+++ b/mm/debug_vm_pgtable.c
@@ -30,6 +30,7 @@
 #include <linux/start_kernel.h>
 #include <linux/sched/mm.h>
 #include <linux/io.h>
+#include <linux/vmalloc.h>
=20
 #include <asm/cacheflush.h>
 #include <asm/pgalloc.h>
diff --git a/sound/pci/hda/cs35l41_hda.c b/sound/pci/hda/cs35l41_hda.c
index d3fa6e136744..990b5bd717a1 100644
--- a/sound/pci/hda/cs35l41_hda.c
+++ b/sound/pci/hda/cs35l41_hda.c
@@ -13,6 +13,7 @@
 #include <sound/soc.h>
 #include <linux/pm_runtime.h>
 #include <linux/spi/spi.h>
+#include <linux/vmalloc.h>
 #include "hda_local.h"
 #include "hda_auto_parser.h"
 #include "hda_jack.h"
--=20
2.44.0.rc0.258.g7320e95886-goog

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20240221194052.927623-2-surenb%40google.com.
