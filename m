Return-Path: <kasan-dev+bncBDQ27FVWWUFRBTFCRHZQKGQEHP5PXHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 90E2517BED9
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Mar 2020 14:34:05 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id p25sf1402942pli.7
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Mar 2020 05:34:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583501644; cv=pass;
        d=google.com; s=arc-20160816;
        b=Qa9j60XUND1INZDdYdEPpuCHWlqJjBAHO0tgzujSJaA7jqT8L9dteE/1DN1J8JkLMn
         WOhVVPUjx537tX3mWVhPG8FtEANw+Za34gFFUEzzzIJiSlMeiRsw1QlKayQZbjBh3WOF
         aBmPD1voJJJ6Xe6DD91s/Y94M1n4F8JwVhyhbhuaEP4XCdmDxMg9Tcd6tJwgVZcmcUeS
         wXoo5hF5HkufP5+O5QSLp39PvxjoBV7PWWnnz9ez7oQkkUptA6LWwbEaVdKMj/0AgUAI
         VjOYPC4LYFEv0bKRvehSW5OZjO3QHgw3A4/BTn07+5flhLRWjXb7/6Rd4sxOj4lZCCqv
         qtsg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=R6ya3eVinEtULeplNqQKvfHb2cajj5t5msUWRxE28/s=;
        b=iCFoET5AnXbkm3pHOj9xG/ChB/RzU/gi3r2hEukaR6z+skhyCHNF7kmGR5STFlaRZz
         xYbgbg2UYo95zfONuGBPQzHAMncU+upbA27SlUxCGtcIZ1zvpvUqzJjMxq+NqUo0J+dP
         HijWF+7LbPTveU1uTbH5fWfG4uYtVoCnhlIcOtYITWgFIhlBWABhGoBYoGcxVAuxS+4M
         Ypjf9qOXZopRpzP82RI4RpwQ1FD3y72wKgmlqC4uxZZMV0auRXU5Wk2n8xLvQvQCGwbB
         fB+P6hvg/Z3GPVW7XoHeFUmFZB4u5kVf8lc9g5V7ZLHnHjTI7GzDvb9dBCegfEo9thx1
         VYXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=CWFn0tyD;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R6ya3eVinEtULeplNqQKvfHb2cajj5t5msUWRxE28/s=;
        b=Xec1K8gcEuflrr1Bgs7w5J/JVf//J6NU7TQM1nRanW4nvU0Jom4hgW8k6tZiEVP67Y
         m30FdL8LHrGB6fuMmEjvyPYg+4E2yVsVP+RE1N+7G3/jikAYHfwudw391q4zuJljn9j+
         V0d16j7T/5MjWOJLeAlCN3jJ0jcCgji7uS90oh5ryYSxQC+L/jGrxMnYEvOSd8XOHGMu
         qUh4PC1nNhKmjuFNJ4jEY8W1HKVR7S66/hEjMzFxoomsPKwVJMA+LEibAG4ENM24snzw
         gU3utetXTl6m4YZGP7KE8bWeVhsen/nm6D82LuNl/04IHycWxNXtnxMXnZZy1j11pbg+
         raWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R6ya3eVinEtULeplNqQKvfHb2cajj5t5msUWRxE28/s=;
        b=fBQ328ISXKvNHdfZVwxma2xbkNnVm3M3W6hK0IpZ2FifBF3uBhY+kdB6S3JqqyIJ5v
         sCEUiIgzf5AsefZpud6SYfFQRDe38Z62g93AK2orMHhShaCyQjEK3VkW9fr0/d35fkZZ
         qlJe4bpXOORpUg+MhLmKUyuUQALItJ8QeaJplofCUc9ixdfwTLWjUNigtNv1Jzaezucb
         3GYWpMdNaOs2K7175Gwqqno3d20ZQNW6SnVK/cw2b8RhJHcUQ6fmccpYR1T9cJx2PG5a
         thyoTW9EcNey7Ft5IfJz7AYzKMF3lpq+2mR675Uywg1MdZpiUbFachztrc2PBlaWWqOe
         kx2w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ1AGj629Wdp9uKmsd/eTU514tvK+Rv4zZ0PLotCo8aFDgX06oKK
	NtBHBIRPC7Q/92JQ3fx0KXs=
X-Google-Smtp-Source: ADFU+vs7EaOLNr8OWJ0R9jFdf8VOZaJtjmyvS3bjzLLQ7+K8r5Hdt1+QgK2OdhVPLyWMW85cookdrA==
X-Received: by 2002:a17:902:a715:: with SMTP id w21mr3065259plq.244.1583501644291;
        Fri, 06 Mar 2020 05:34:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ab86:: with SMTP id f6ls998829plr.10.gmail; Fri, 06
 Mar 2020 05:34:03 -0800 (PST)
X-Received: by 2002:a17:902:5ac9:: with SMTP id g9mr3142097plm.125.1583501643858;
        Fri, 06 Mar 2020 05:34:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583501643; cv=none;
        d=google.com; s=arc-20160816;
        b=cC3qrcekaavEpxfNz5ZFXAPGozStjcElYT4VtVKUHPpEvuyR7JZFSWUckmgTvarZnc
         hE9TxoshYnOTPbAtO3geI0aVUdVvZfx/cEmByTYZ3PV8F42a/gK5jfYQS4tR0HCFcL8T
         ghNN8B0A05GTWlGgXgvSzwungIUhTPkXICFYO+gcANQUlFNu30EYXheJytirkqeD4KEp
         wrXsHmMhQ6pU47IDjK36SsIPT5Jr7gEzUEAGoYx5hdysXGmb0TCdEzYixN8YWpWkVAsq
         d5X95QTPS6Dfqpfa5lz9mvw0nNlCGPXFOZ/jyv6LfAVUrD2jDJ6/EsERK1fuj4yyc2pp
         DPWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=CaOpE+RnykMge29WfCqnRai8zpZuPSzzYfJQc7CCb6s=;
        b=uozsUnfOrS7xZZxmBilgDoa5n+rcJF+oZitl8xOqxtnCcXpLi5fnnASLrFSuy4XRTa
         /8PkUq9b8+WjAlgj47YrgjQO0qvrMO+6DPOmOB/fvtdocjFA8dFqF6lNRjY4A4lmh8qK
         5kjKlIrpQiBS3GQwufNMSbaMPm6lEvuCGs9rky3BOqhUsZKpBcX8aJdaljHFuBjbEfM2
         F7HqDwC1VEFho6JkAMjHbHxQCZeP1gaSG2fI7vWDhx9a9w25aL2JljHYlgD/vMqGk520
         ppDl+bsmIYaz7CpOkQkCZLzCn5WsUH1lvhDfKhjDp9laYXbcuSEl1HsNliSHely3vPV3
         kFrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=CWFn0tyD;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x544.google.com (mail-pg1-x544.google.com. [2607:f8b0:4864:20::544])
        by gmr-mx.google.com with ESMTPS id q197si145808pfc.5.2020.03.06.05.34.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Mar 2020 05:34:03 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::544 as permitted sender) client-ip=2607:f8b0:4864:20::544;
Received: by mail-pg1-x544.google.com with SMTP id 7so1103343pgr.2
        for <kasan-dev@googlegroups.com>; Fri, 06 Mar 2020 05:34:03 -0800 (PST)
X-Received: by 2002:a63:3d48:: with SMTP id k69mr3197323pga.395.1583501643532;
        Fri, 06 Mar 2020 05:34:03 -0800 (PST)
Received: from localhost (2001-44b8-111e-5c00-b120-f113-a8cb-35fd.static.ipv6.internode.on.net. [2001:44b8:111e:5c00:b120:f113:a8cb:35fd])
        by smtp.gmail.com with ESMTPSA id h4sm10196858pfr.107.2020.03.06.05.34.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 06 Mar 2020 05:34:02 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@c-s.fr,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v8 2/4] kasan: Document support on 32-bit powerpc
Date: Sat,  7 Mar 2020 00:33:38 +1100
Message-Id: <20200306133340.9181-3-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20200306133340.9181-1-dja@axtens.net>
References: <20200306133340.9181-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=CWFn0tyD;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::544 as
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

Changes since v5:
 - rebase - riscv has now got support.
 - document s390 support while we're at it
 - clarify when kasan_vmalloc support is required
---
 Documentation/dev-tools/kasan.rst |  7 +++++--
 Documentation/powerpc/kasan.txt   | 12 ++++++++++++
 2 files changed, 17 insertions(+), 2 deletions(-)
 create mode 100644 Documentation/powerpc/kasan.txt

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index c652d740735d..012ef3d91d1f 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -22,7 +22,8 @@ global variables yet.
 Tag-based KASAN is only supported in Clang and requires version 7.0.0 or later.
 
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
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200306133340.9181-3-dja%40axtens.net.
