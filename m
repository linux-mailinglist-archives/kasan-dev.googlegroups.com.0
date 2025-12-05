Return-Path: <kasan-dev+bncBAABBHHFZPEQMGQEUAE75AI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb13e.google.com (mail-yx1-xb13e.google.com [IPv6:2607:f8b0:4864:20::b13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4151CCA8085
	for <lists+kasan-dev@lfdr.de>; Fri, 05 Dec 2025 15:56:31 +0100 (CET)
Received: by mail-yx1-xb13e.google.com with SMTP id 956f58d0204a3-63e29ad5503sf2833620d50.2
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Dec 2025 06:56:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764946589; cv=pass;
        d=google.com; s=arc-20240605;
        b=a/sUsue+yXqxXxkXwvXohv3qo2Jy5DdBlRwxf70mLXR2qEd0GXjQ6YULefaxRmvZPN
         n6b5pyvfhOhw2qlEU8unFr37DT84qIQpKhR+cwvvoGS96krcDK5xEeXR9sV/6rVlEYAu
         dxYX7q5sB66dwoDJcD1Mni149EHTIHY/cOvYtLQnof58dS3OTn8KF5Ok14MNSk97iWs1
         LZzcPAtXtH5poWMOzj4a8xo1W8fJT+XF3ffz5b1yz4qo+E6D90yTA8YrBEF9Tx0WVYHv
         H/OMiFw/sacCDKaJL7ke8+RKHje7t58c3yO/CFOkfVedw8Rc17xZ0bCUlAnFAmC/RbYT
         V5Dg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :message-id:subject:cc:from:to:date:dkim-signature;
        bh=v+vwV0CM0/oJUAZRcgjx5RCahnfy5N4J/YK/E3ADHGY=;
        fh=wuctSbLhei3AOSjaE9idxBO74cv5FHR65Yn4+KCThEo=;
        b=Pb2NazasC/1iHjxmiG2Z7RCQ7BKSIiw5kqDE12iMxpZ1pvn6zmPrkxQgvqGqCfC26s
         CkiEXb79MLc55u7ixfMotkjGmYr92uWG0w2n72UHlVfdS3VCkKA4HGxbN/cTUwrdHXDU
         LiYgR7A22sqA+11J3/DHsdIhDwq0HkOedaCRQVmsV7CbfidaOe6oZIM2zZVDtPZT7Mpf
         E4XZGGlDJTFKflbJg4tznewLejDfyX98ixtSOgnO598lwgbP2fGmMBUnBz5/mmIiHGhx
         mX5t2726DIRoY/WARQ0mf4EwBImnKp1YOIgD/yjNJ2anRAQhLURctUfz/oZUMhVN/Pp1
         Eszw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=XwvPcXci;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.123 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764946589; x=1765551389; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=v+vwV0CM0/oJUAZRcgjx5RCahnfy5N4J/YK/E3ADHGY=;
        b=fyjBrz5jsgDnZHo+M222k7vJDxrMHOJc7vuEnZL9yxjfUTSNvy6stYqK+Sw622he49
         szjoU+bUKWneZuyDPQm5riCMIGQfQE71ZPc48rj8W7Zmzt1+cgCCJmf78z3T4Fp6W+Yx
         YzDMHzJkDPGXUTfy+CCJdAKjXc0SPbQDeMfaC7sYLDfZNjR4H436we8KRl/C9mO0QMj6
         ofCF/Qo2jiRWhodwPOL/bslrrFTRyQ50iO+MT4DNlEH/ryfjlEOwTTOokdCPzEQkH8rY
         Eqo0jpv/yWoFMYRWhZlHOxQtxhyRYcv0++dHlv19BmHxTybv7rtbVQ/LC9uKlDGxt5qf
         GWVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764946589; x=1765551389;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=v+vwV0CM0/oJUAZRcgjx5RCahnfy5N4J/YK/E3ADHGY=;
        b=hVKsI419B9YgX7+nN8h6WRhFJ1oOJ5lhdS2mFSBD+zLWRquPBRqTlRpINpH841UbWn
         FYACAoC2oEoG5KyIhJHBx9lhslgLAM9ti/6qBz7G0Ysi4/pUqIWUGtJYwGiLpQMhObHi
         T5MHCUPjwP51TDUoEUHUEJayNB8LbK1CdtkXJ97siElk1m3Mv3OyY/nknkJ+c711SJpo
         jbDZeaWdK/4ZJqLGVslOtzW5AiB1rHHT2oYI8spld7fPRxhIVByVj4gFhINsvqXlkY0K
         wir1GliKyM9bS5H3aWkQaX0Z8d9GRBhufBxAzF9B3RNxyO+gojLG0U/memRRTshT9fox
         KdgA==
X-Forwarded-Encrypted: i=2; AJvYcCU0QvBB9WkIfCTrpqk7BBcU/DXR0dSlyzzKpn75RT4lP09hiWDtfSLc9tq6/2TASEKy2DQSDg==@lfdr.de
X-Gm-Message-State: AOJu0Yzx6WqDiFOZ4zEYWJApjUgXT1ZcOffPoWCM5qJhZt1wTymWcm9k
	Zc4MSyiWpJH8jvdCTo/hXjLTUTn+qI2iIobgA9SwnmKeqYMKGN363HOp
X-Google-Smtp-Source: AGHT+IHH5MdPkYdY6x6zwm4xEJXQ9Yejv+0HOvGt7WSvAXFtmO+aei4bJEQExOWGO5EMFx3QiJWWow==
X-Received: by 2002:a05:690e:144e:b0:641:f5bc:696d with SMTP id 956f58d0204a3-6443704c3fdmr8106051d50.73.1764946588864;
        Fri, 05 Dec 2025 06:56:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYoWfhnOrMJHURPQcXDzvDTIM+Uz6VWXXsTvmXOBujZng=="
Received: by 2002:a05:690e:169e:b0:640:d382:f1a0 with SMTP id
 956f58d0204a3-6443e894522ls1925359d50.1.-pod-prod-01-us; Fri, 05 Dec 2025
 06:56:28 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUhJtHNcJvJTsh2c6tWG8hDFAg6e0+kz0FUCIyCpt9loRfw53yMECT9MkNWQDqVvQGzu1XfWkfONDw=@googlegroups.com
X-Received: by 2002:a05:690e:b42:b0:63f:b56e:74c6 with SMTP id 956f58d0204a3-64436fab5c7mr7496667d50.19.1764946588092;
        Fri, 05 Dec 2025 06:56:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764946588; cv=none;
        d=google.com; s=arc-20240605;
        b=gEFDQQh6mrCECdbNbqWH1gLNwXAMh7fU2YGSMxnnpDjFdRRdSCQgZOGFbPinqW+Lx2
         Vx+vye8kPGYrmZbV3E2JnHTiUgZtChg8Xpwz0MMDFRbwhVZTdiuY3u+N3kL3dyZe/6G/
         yT/d9mLxkd2I1+Z/ylp8GuAtFEzAvVbn80vPUvzT+h1cvs6QBKChKn6VhFdCyXdGOwBv
         gX1mKWosQi+PaMYLIoQTueJn5w5yOkRzraE+anks+8pv4WTNkcthgb0ykWWlqCrIAeCw
         fT0+oeFhQZdzdlG0NndEUTwQWJQG5juMgfiTkZ1/gyaqlXQuvGn/nl3aqGlIHSQDAJhG
         +a0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:message-id
         :subject:cc:from:to:date:dkim-signature;
        bh=383jLSyvcX9dMsFb72iSsTG6CU8UwzEbp05NdSalEfc=;
        fh=W8OWxKC9+GAbr2iSZMxS4r6YldebeeYm5t0Yk+fEP2A=;
        b=HlvqE7MUVX+/ziZfsITbWgRqKCnLqIO6u7dPaMUbVFJJHrPYEhEzkhsUK0Ab2TuMe7
         OBlphV0BhEY+hyu5SGiDNxfwpYmOuQW5RCO+gqUo35LbMs5i+kMlzlW9dIV5n5aAZd01
         cbHd9QfVBVHR79YrLA3nM9Y5iPUWCd58tBIOF8Z3uMC+CDJ3CMr1gzKlQ0/u62qt8ucJ
         owWiBXcyM8juurbK2RM1Tfd7np2PsX2KlhhQ3z6/ep8vIr0RkMgJsA7TkpX/LDOqBfp+
         3oVjERs/SN7+pb6f8wjlStkktFURneOk9hz7JAesQ2gYWfv1KU4hN6750bezfWICDVyr
         nqIg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=XwvPcXci;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.123 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-244123.protonmail.ch (mail-244123.protonmail.ch. [109.224.244.123])
        by gmr-mx.google.com with ESMTPS id 956f58d0204a3-64445c84a1asi75165d50.1.2025.12.05.06.56.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 05 Dec 2025 06:56:28 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.123 as permitted sender) client-ip=109.224.244.123;
Date: Fri, 05 Dec 2025 14:56:19 +0000
To: vincenzo.frascino@arm.com, ryabinin.a.a@gmail.com, urezki@gmail.com, akpm@linux-foundation.org, dakr@kernel.org, kees@kernel.org, glider@google.com, dvyukov@google.com, elver@google.com, andreyknvl@gmail.com
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: linux-mm@kvack.org, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, jiayuan.chen@linux.dev, m.wieczorretman@pm.me
Subject: [PATCH v4 0/3] kasan: vmalloc: Fixes for the percpu allocator and vrealloc
Message-ID: <cover.1764945396.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 2953a64df10d9b54e8549fd874bdc490c4648bbe
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=XwvPcXci;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.123 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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

Patches fix two issues related to KASAN and vmalloc.

The first one, a KASAN tag mismatch, possibly resulting in a kernel
panic, can be observed on systems with a tag-based KASAN enabled and
with multiple NUMA nodes. Initially it was only noticed on x86 [1] but
later a similar issue was also reported on arm64 [2].

Specifically the problem is related to how vm_structs interact with
pcpu_chunks - both when they are allocated, assigned and when pcpu_chunk
addresses are derived.

When vm_structs are allocated they are unpoisoned, each with a different
random tag, if vmalloc support is enabled along the KASAN mode. Later
when first pcpu chunk is allocated it gets its 'base_addr' field set to
the first allocated vm_struct. With that it inherits that vm_struct's
tag.

When pcpu_chunk addresses are later derived (by pcpu_chunk_addr(), for
example in pcpu_alloc_noprof()) the base_addr field is used and offsets
are added to it. If the initial conditions are satisfied then some of
the offsets will point into memory allocated with a different vm_struct.
So while the lower bits will get accurately derived the tag bits in the
top of the pointer won't match the shadow memory contents.

The solution (proposed at v2 of the x86 KASAN series [3]) is to unpoison
the vm_structs with the same tag when allocating them for the per cpu
allocator (in pcpu_get_vm_areas()).

The second one reported by syzkaller [4] is related to vrealloc and
happens because of random tag generation when unpoisoning memory without
allocating new pages. This breaks shadow memory tracking and needs to
reuse the existing tag instead of generating a new one. At the same time
an inconsistency in used flags is corrected.

The series is based on 6.18.

[1] https://lore.kernel.org/all/e7e04692866d02e6d3b32bb43b998e5d17092ba4.1738686764.git.maciej.wieczor-retman@intel.com/
[2] https://lore.kernel.org/all/aMUrW1Znp1GEj7St@MiWiFi-R3L-srv/
[3] https://lore.kernel.org/all/CAPAsAGxDRv_uFeMYu9TwhBVWHCCtkSxoWY4xmFB_vowMbi8raw@mail.gmail.com/
[4] https://syzkaller.appspot.com/bug?extid=997752115a851cb0cf36

Changes v4:
- Added WARN_ON_ONCE() and removed pr_warn() from last patch.
- Added missing cc stable to the first patch.
- Fixed stray 'Changelog v1' in the patch messages.

Changes v3:
- Reworded the 4th and 5th paragraphs after finding the vms[] pointers
  were untagged.
- Redo the patches by using a flag instead of a new
  __kasan_vmalloc_unpoison() argument.
- Added Jiayuan's patch to the series.

Changes v2:
- Redid the patches since last version wasn't an actual refactor as the
  patch promised.
- Also fixed multiple mistakes and retested everything.

Jiayuan Chen (1):
  mm/kasan: Fix incorrect unpoisoning in vrealloc for KASAN

Maciej Wieczor-Retman (2):
  kasan: Refactor pcpu kasan vmalloc unpoison
  kasan: Unpoison vms[area] addresses with a common tag

 include/linux/kasan.h | 16 ++++++++++++++++
 mm/kasan/common.c     | 32 ++++++++++++++++++++++++++++++++
 mm/kasan/hw_tags.c    |  2 +-
 mm/kasan/shadow.c     |  4 +++-
 mm/vmalloc.c          |  8 ++++----
 5 files changed, 56 insertions(+), 6 deletions(-)

-- 
2.52.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cover.1764945396.git.m.wieczorretman%40pm.me.
