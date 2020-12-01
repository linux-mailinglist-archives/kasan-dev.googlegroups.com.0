Return-Path: <kasan-dev+bncBDQ27FVWWUFRB5WYTH7AKGQEG4TUKHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id CAACF2CA7F0
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Dec 2020 17:16:55 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id l5sf1365330pjk.9
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Dec 2020 08:16:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606839414; cv=pass;
        d=google.com; s=arc-20160816;
        b=uDWhBsEkhbxSl4c+NZ0dC/8s+VmY5grpuEBnDFeDvx6ECA41Q3UBgBLJBJtb5vfPdV
         h61ocbjMR0ZdkC4Zt/Eg00CpaL20EmNnemeWNWo6WyklT3oS4lyMhYecfLiFgx4BJiQe
         n3wgs1SdfIlGceuaeJxeW3Ew3TDl08ckiOAnKXgNkdHDhE/pPTz6JWZQVyYRp0TJ/cgE
         Uq3WRnOcFfss3wj07Bq2WdCs7VCGdShlWljz726NH8OuOwd0HhNtg5mZiuPtonLLB2kd
         emxLC6eZs1MWqheIuM3L6CO8ymXp0Y2bML/z3rwcFJPHBpfCjBq/EFWh0vn0OwcNb3EE
         AZKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=cOu19zIoP+uP9SMsH2mshtzbVtGHMnISXz4CIXpL8PE=;
        b=IS0oXr6biPkGiyE10bjoJ1O2iHzAL68cmCnYDiMUVFBdU8kSgXlVDUZmmiranvRbNR
         jhFQVJKFY2ZuKaPs5d8UC0Tjmya8jGErd76ic4xo3f/k1mdYC5BvOJWwT1xWyHlkH6H6
         i7VNHhrjid6w5uzwMpnrjNielYKhpShY5vmJZb59/VwxfUUXiOIJd7UuUClwSh4wzuR7
         3SJEeeCCQNpLVpe5eIn57tLoELCGKWuAFV33VDM7dd85QE0s8YPZdX3SkuLmR3gzQp2c
         m8XoNBQJIVIxXnjOnpaFZGv9Yl7fv7O/M42/Ygdlvp81bK3d9kql3R3fqF1IteeYtB69
         axjw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=IHx2W6Gs;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cOu19zIoP+uP9SMsH2mshtzbVtGHMnISXz4CIXpL8PE=;
        b=DZUcfnV61LOzwBIWJgqH0SU6N+7TETjta+ODhfRn7BWAMs16BoS4RodtB69BthMd11
         4qDQ0q7rC+qJUqnfxtOfLzKndnF4z6kTbK80jEmsAaynUfyW1ej+81pyxvPDigu3JbHF
         1peFKVySxfX2lTdIGTTryAgeTlceoz4GzeZE7eZTh4+BmySRVgM97frUqAiGQzKOf29O
         mRz9bn6VWok+CO+aMki0VtrlE6IjgdY1AKwalzUk4FxMlgokJ9TfVvKx5y4z/NH4GbAt
         ECkl2BFc69596Z6mVapgLiUyEyVjmpwPEyUBFFKdXdK7jAGg18kYAus6Qf+KxeTTKp+r
         0vIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cOu19zIoP+uP9SMsH2mshtzbVtGHMnISXz4CIXpL8PE=;
        b=Qs4K4IS1zUvTqv3NZlFN2ApgnLtiMxvFwpYmakKvbxGh8U5FyqZgJftMfMOBMDx1q1
         x/kQ88EQCRDQyB3qirCyTp6oSxiD1HUOWDtsRBUWie5/CLkNzM7QdYLzaXMR7okIAzRr
         K20DjEFWrPlFuIN2zMiYEvgM305UJTasmRFl9AweeU0Sl3lOh5xRUwgE1bJLs0Ixs7n5
         U22hc5dbHZ4+PcjqhnFj8KubfAAWvTtJpjCZ1yml6SK7fBusW+tkLvYeUMeIY52fHvHg
         5kNqin8fFkTcf22iTzxQSN0/5Fsb5zSU0/rQK0Ud9KUCVtIU2Q0m0wLBAS4GDIPDQsNP
         s10A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5331DpvNyJQP+nDSDRT0nIDT4uxIAnHn/yGacWIwhCYlTU0J5N2W
	2kTcK+CQaqalqFL9XyqzAb4=
X-Google-Smtp-Source: ABdhPJxknBrcaYX2sfzLw0+blNJDswCkgPBxnUGnzWgynT0saWhM9CNrTDk5iE9j31Dz665o5J2HUQ==
X-Received: by 2002:a17:90a:aa13:: with SMTP id k19mr3508010pjq.145.1606839414622;
        Tue, 01 Dec 2020 08:16:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c253:: with SMTP id d19ls1501278pjx.2.canary-gmail;
 Tue, 01 Dec 2020 08:16:54 -0800 (PST)
X-Received: by 2002:a17:90a:aa14:: with SMTP id k20mr3405530pjq.131.1606839414078;
        Tue, 01 Dec 2020 08:16:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606839414; cv=none;
        d=google.com; s=arc-20160816;
        b=xTLUHvXJ45srfKZyGBLRsJkKRIE7y+gmdD5/2UvlUC9WJFaiJ/A2sVmTsxaLJNyZfh
         SAorX1/xXbkONWcWEB9xWP3JL76JXTX9WxuOcWVntIgZ6rmqKwpmINorhq2Qkt4rWVJE
         JIjM/YFWJ7r1vdbsi8HdTlzPc608k8DmNMzVLWvG8O5xvaUbSU5JYR3Ef/85wlnIv2UW
         XJIkEi8IolcFQp1wor22T+/UV2e6YHdgTU6KnayKtFno56Q1vkY5mYrlVb2Uf9Lu7npU
         V8Ra5XtknY1AEMJra5wSXFzqr0ngO9qHIUN3raoISvgjzRkEYerrFpKdD+oqr13KfW01
         2rBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=B3cGCHzxS7oj9LZKxlOIS4CcjJY/Vd95YR2IG8LQpYg=;
        b=KYEob+XZne35qQGL/p2wN+rDTNyZEAQxKP44YqNYROeDJ3IfH1ml7ELgqKz3a+x2s/
         h7Y499w0/jOVC3E8m9981EfESNQdLHUIcR9tH4MBcPTmnEFjz2Ivw9SOy3aIYWvySKp1
         OgcMxphq+w3q27qzP39twksKbgTzryoOexCFRERpq9q3pYM/toz8DU7YlJZT9k3pkOGx
         Ax3zKFq69SVgPzD5lJAs2DD1LfPQei+rEc7KURoz/RhMnqNNgd/HuG681HL2sBsxi/nf
         spMLhJ8wzlc9Zanr/DxCiRO/+nH20W6n3DX+rPkweOfHvcZR6q4HrvnDVgZz1MSoNIhF
         kyNA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=IHx2W6Gs;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id r127si15586pfc.5.2020.12.01.08.16.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Dec 2020 08:16:54 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id x24so1422446pfn.6
        for <kasan-dev@googlegroups.com>; Tue, 01 Dec 2020 08:16:54 -0800 (PST)
X-Received: by 2002:aa7:868e:0:b029:197:cc73:6f15 with SMTP id d14-20020aa7868e0000b0290197cc736f15mr3168859pfo.18.1606839413794;
        Tue, 01 Dec 2020 08:16:53 -0800 (PST)
Received: from localhost (2001-44b8-111e-5c00-f932-2db6-916f-25e2.static.ipv6.internode.on.net. [2001:44b8:111e:5c00:f932:2db6:916f:25e2])
        by smtp.gmail.com with ESMTPSA id p14sm64656pgm.69.2020.12.01.08.16.52
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 01 Dec 2020 08:16:53 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@c-s.fr,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v9 4/6] kasan: Document support on 32-bit powerpc
Date: Wed,  2 Dec 2020 03:16:30 +1100
Message-Id: <20201201161632.1234753-5-dja@axtens.net>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20201201161632.1234753-1-dja@axtens.net>
References: <20201201161632.1234753-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=IHx2W6Gs;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as
 permitted sender) smtp.mailfrom=dja@axtens.net
Content-Type: text/plain; charset="UTF-8"
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

KASAN is supported on 32-bit powerpc and the docs should reflect this.

Document s390 support while we're at it.

Suggested-by: Christophe Leroy <christophe.leroy@c-s.fr>
Reviewed-by: Christophe Leroy <christophe.leroy@c-s.fr>
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 Documentation/dev-tools/kasan.rst |  7 +++++--
 Documentation/powerpc/kasan.txt   | 12 ++++++++++++
 2 files changed, 17 insertions(+), 2 deletions(-)
 create mode 100644 Documentation/powerpc/kasan.txt

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 2b68addaadcd..eaf868094a8e 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -19,7 +19,8 @@ out-of-bounds accesses for global variables is only supported since Clang 11.
 Tag-based KASAN is only supported in Clang.
 
 Currently generic KASAN is supported for the x86_64, arm64, xtensa, s390 and
-riscv architectures, and tag-based KASAN is supported only for arm64.
+riscv architectures. It is also supported on 32-bit powerpc kernels. Tag-based
+KASAN is supported only on arm64.
 
 Usage
 -----
@@ -255,7 +256,9 @@ CONFIG_KASAN_VMALLOC
 ~~~~~~~~~~~~~~~~~~~~
 
 With ``CONFIG_KASAN_VMALLOC``, KASAN can cover vmalloc space at the
-cost of greater memory usage. Currently this is only supported on x86.
+cost of greater memory usage. Currently this supported on x86, s390
+and 32-bit powerpc. It is optional, except on 32-bit powerpc kernels
+with module support, where it is required.
 
 This works by hooking into vmalloc and vmap, and dynamically
 allocating real shadow memory to back the mappings.
diff --git a/Documentation/powerpc/kasan.txt b/Documentation/powerpc/kasan.txt
new file mode 100644
index 000000000000..26bb0e8bb18c
--- /dev/null
+++ b/Documentation/powerpc/kasan.txt
@@ -0,0 +1,12 @@
+KASAN is supported on powerpc on 32-bit only.
+
+32 bit support
+==============
+
+KASAN is supported on both hash and nohash MMUs on 32-bit.
+
+The shadow area sits at the top of the kernel virtual memory space above the
+fixmap area and occupies one eighth of the total kernel virtual memory space.
+
+Instrumentation of the vmalloc area is optional, unless built with modules,
+in which case it is required.
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201201161632.1234753-5-dja%40axtens.net.
