Return-Path: <kasan-dev+bncBDP6DZOSRENBBC4F6LBAMGQEA2U5BRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 813AFAE91AE
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 01:13:18 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-4a43ae0dcf7sf9177761cf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 16:13:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750893195; cv=pass;
        d=google.com; s=arc-20240605;
        b=DY3211nDIbqs+NjAL1v9PozhyYfPY/7cSx/FxjZvCAj9YF5im+QnQv90FMSwqVnWrA
         CEHxVT1PPFTJFJeGzJbdaYtD9Ei4Nbocrcq3i2sBW+IwyARsK5qw3Lxx6f6ZIBlzZ2JF
         K8odbddKTkpdTm/QGlyyuKXB75LnQzBDLGLr8nPXC1bUqEPupoXFaKsas2FGiPMgpZwq
         VIbWLdCSvDm5l9myUfNaEaS80+jyI9aePMIWINouFegfyvc0F4SeCPPEKybuJMNSML5g
         avyazAM1xOSE4NQwhqfoq0iJFwkaTaL9HypVI0314gRwVsijGF/uJlDnmuCu2XYdzBho
         c1pA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-filter
         :dkim-signature;
        bh=USI9gi/KQQacyg5dR1EO+bHxS0h23A0KwTfBEFPG4m4=;
        fh=hK6oqA1XU1cDEUQrrORFiu9yGp+D8xlSxTuoQLNxrO4=;
        b=Z+x4L17LF1DLsH4DhM+k7D2ehkyVBrcUABQYyYxEsVpMW5rGbWsLMHST7/clusEDnm
         YQi1L3qY0g56JpnZUuYHNMebjqKvZMfrSKmfBfgTFTtARLKMb3JQCQDocH/D/GM8Dal9
         nWvzEzlHKrfxju1dXORXJI/uSgCXYmxCG50Cb5uFeEDg6Inkh6VaCF2DmREgXiZY+g14
         bpLwsrd3+tE9tjrmltkLkt5w5fd1W7AbWLS9FuQyiuNikmINF265r4oBa8e6Mlp8xoCO
         qVmdP388ltPBuDs+epLtj+KzzvwssR92YsUUGhXORaLAuIFgMkmIZWhJBh6+sr3gaua8
         4hoA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=dkimrelay header.b=vDS0zxQ3;
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.207 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750893195; x=1751497995; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-filter:from:to:cc:subject:date:message-id:reply-to;
        bh=USI9gi/KQQacyg5dR1EO+bHxS0h23A0KwTfBEFPG4m4=;
        b=evvBb+9zYZmWJ8qK7VaoV4H5rS/dwvNjGgy1Fp8VbTmgavcpCneRHUjNd6IQ0pyrDf
         4G/fjKU6/nC5qZh8h59bX5YSg0+44SiA+cbB68xmS+irUb0VwBqEkD26jhw24EZL1de7
         u2x4ldtWaV4ggSoI+pTpPa+lALnk6Cl3wkzcCyISG3KFxvzXYbV4HF7iU+ArFt7emkjU
         FpLRE4qxMSCyFNz04aP+vjTkrFuZ4WzAJW2wnB8TI2jtKWtlVSr9aQ1Fwx/1o9sdRO4Y
         sg6SbRkBnB/cG5XEjrQ4OXr0RAfO41x6yH8oJFLs+1m1OTLqeYrvWc+rFut9eo13iMHA
         hpvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750893195; x=1751497995;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-filter:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=USI9gi/KQQacyg5dR1EO+bHxS0h23A0KwTfBEFPG4m4=;
        b=D7lIwdfrFpo+F2mHD7sMrG7MQmW5TTRhMk/F8gcKbUMakmx/A30URwpI/WurttPtAw
         +KaNMQeYcsKqV9SQMQsgf8vE0h4HNK7bRGJH2OyhXfL8Vi8OIFjRLNxDTOntvU5knpwm
         bPpbWDejZAcCkroCn8iIFj4izcTr7xWHixMwFfA2sr7ikGSsuRGTSMGpK+jlPpCWm9fi
         YPpAXeOYL1iWBFe3ecL4ScvDlh1f3TSlOUlVY/gIppOU0A5/HLLm+RZUKODvJamc9c8z
         tpks58nsC+OTb0LGQfCH21JcepTcrHxrqMJcxIcuWCprRNo0lV9VGG4joZMQ5bXAahTm
         9NDA==
X-Forwarded-Encrypted: i=2; AJvYcCX/cV0KEvD2E6Lhv+OgDN2W9kS1A+uzO/ByeAbhKcql5frPsl8IL9BvrsfG35XrivXKLrdwdw==@lfdr.de
X-Gm-Message-State: AOJu0YxReKWoCLbUhGM5GFJFf+qiK7jasXYOFv85HRh//w5D2Mo2oFg0
	nTi/wX/BDq8n3cL+HvMTeQwjQSuUWpROcLJR7Wxm/pKrTjTjpyX0rcww
X-Google-Smtp-Source: AGHT+IGsa0dTI6rhCNNsdu9rO3pFu+gPj/goBLJ3yrABh8kByHadorgJLuVBWjfXWuAN/eWCsi4T3A==
X-Received: by 2002:ac8:7fc2:0:b0:494:abde:2aa3 with SMTP id d75a77b69052e-4a7f28ac2dcmr28018531cf.18.1750893195686;
        Wed, 25 Jun 2025 16:13:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdeLo3chqRYHlOt7hxBvEu9MxF3m5YPlAkajoviHdskrg==
Received: by 2002:ac8:5e47:0:b0:477:78b2:dc08 with SMTP id d75a77b69052e-4a7f3101655ls4780061cf.0.-pod-prod-01-us;
 Wed, 25 Jun 2025 16:13:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWmnG8uDYRCfPIvBBa0unBp9o8VsbTh89Ji0SYZ7YGeRVwrdxcOOIayjaurTAkrvdVR5t3AaaAgecI=@googlegroups.com
X-Received: by 2002:ac8:7f11:0:b0:4a6:d5ae:8901 with SMTP id d75a77b69052e-4a7f28ab1abmr27255841cf.19.1750893194704;
        Wed, 25 Jun 2025 16:13:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750893194; cv=none;
        d=google.com; s=arc-20240605;
        b=c2ii/vB/siQxjIishZWprdqeJ1PuWJ6PZE+jF+RHGSbQ5CyExjTBOKBeSiE5l3PJ96
         WRBiyOpL26+gW0te/hbiLg1OFUCLXc6mEaUMpYgGOUHTmmwSNX7y2/HFKcssD/iPSv61
         ho+wMWtA53F4ANMsgKPJnJ8BMkC4Zvta+VU31NnqkwCPTQt9rmF6jSgNya2cfTV8ZipC
         L/wSX1Az6cS+yLtp8H0PGHcp350hisn2yDbndkrguWtkHIC8Z/nqvrtDQ1v5H/ND88BZ
         Bdq7PoE+MX0cMuspBjkL5HclvPLVCNYl63Uz9j2mO+0Fy/7O/UMX+wf+1AnWaPEWxnKm
         8RFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-filter;
        bh=t79Pz8UZVnLtwvLCCxQakJ6VD/QuMCQka2OWL/YnAFM=;
        fh=OYnYQ2Qi4AglTmqWgAhKJslZrlWtos4yS7cvABM55lU=;
        b=fuIBZ/3YU72AhOKFq/9AzlOPW9BGtOKYjis1o975Wws52gt/KOIyZaTm4/MdqMBrp0
         FpKZiYQ+Tpo2YIGKY4VoSTL2uR2cWbK02pSgC9KesteqT+PEjmEQ9HPx0VEpyZ+oJCOj
         420yzG8JBZwnnzZh4lWw+/QGPfAAqzAdPIyPZoYCWuPoTrIcNfVSinn53smsAOxJLpKw
         EN1sLioSu3gdGNjWFKgIEhEKuYAb4C62K+o+K5vcTEyO8Ynn+hgCo6YTsJVqtyakL6vd
         5ZBlbfJTMEaTrBO4pBPR7pZhAXx851c2fznODIXiV5i8J43+dBRaC5AsveJj4GgqHyCc
         Mz+g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=dkimrelay header.b=vDS0zxQ3;
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.207 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com
Received: from relay.smtp-ext.broadcom.com (relay.smtp-ext.broadcom.com. [192.19.144.207])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4a779e19a6asi6746511cf.1.2025.06.25.16.13.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 16:13:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of florian.fainelli@broadcom.com designates 192.19.144.207 as permitted sender) client-ip=192.19.144.207;
Received: from mail-lvn-it-01.broadcom.com (mail-lvn-it-01.lvn.broadcom.net [10.36.132.253])
	by relay.smtp-ext.broadcom.com (Postfix) with ESMTP id 50141C003AD4;
	Wed, 25 Jun 2025 16:13:14 -0700 (PDT)
DKIM-Filter: OpenDKIM Filter v2.11.0 relay.smtp-ext.broadcom.com 50141C003AD4
Received: from fainelli-desktop.igp.broadcom.net (fainelli-desktop.dhcp.broadcom.net [10.67.48.245])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mail-lvn-it-01.broadcom.com (Postfix) with ESMTPSA id B8AF118000530;
	Wed, 25 Jun 2025 16:13:13 -0700 (PDT)
From: "'Florian Fainelli' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: Florian Fainelli <florian.fainelli@broadcom.com>,
	Jan Kiszka <jan.kiszka@siemens.com>,
	Kieran Bingham <kbingham@kernel.org>,
	Michael Turquette <mturquette@baylibre.com>,
	Stephen Boyd <sboyd@kernel.org>,
	Dennis Zhou <dennis@kernel.org>,
	Tejun Heo <tj@kernel.org>,
	Christoph Lameter <cl@gentwo.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	"Rafael J. Wysocki" <rafael@kernel.org>,
	Danilo Krummrich <dakr@kernel.org>,
	Petr Mladek <pmladek@suse.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	John Ogness <john.ogness@linutronix.de>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Ulf Hansson <ulf.hansson@linaro.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Luis Chamberlain <mcgrof@kernel.org>,
	Petr Pavlu <petr.pavlu@suse.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	Daniel Gomez <da.gomez@samsung.com>,
	Kent Overstreet <kent.overstreet@linux.dev>,
	Anna-Maria Behnsen <anna-maria@linutronix.de>,
	Frederic Weisbecker <frederic@kernel.org>,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	Christian Brauner <brauner@kernel.org>,
	Jan Kara <jack@suse.cz>,
	Uladzislau Rezki <urezki@gmail.com>,
	Matthew Wilcox <willy@infradead.org>,
	Kuan-Ying Lee <kuan-ying.lee@canonical.com>,
	Ilya Leoshkevich <iii@linux.ibm.com>,
	Etienne Buira <etienne.buira@free.fr>,
	Antonio Quartulli <antonio@mandelbit.com>,
	Illia Ostapyshyn <illia@yshyn.com>,
	linux-clk@vger.kernel.org (open list:COMMON CLK FRAMEWORK),
	linux-mm@kvack.org (open list:PER-CPU MEMORY ALLOCATOR),
	linux-pm@vger.kernel.org (open list:GENERIC PM DOMAINS),
	kasan-dev@googlegroups.com (open list:KASAN),
	maple-tree@lists.infradead.org (open list:MAPLE TREE),
	linux-modules@vger.kernel.org (open list:MODULE SUPPORT),
	linux-fsdevel@vger.kernel.org (open list:PROC FILESYSTEM)
Subject: [PATCH 16/16] MAINTAINERS: Include vfs.py under FILESYSTEMS entry
Date: Wed, 25 Jun 2025 16:10:53 -0700
Message-ID: <20250625231053.1134589-17-florian.fainelli@broadcom.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250625231053.1134589-1-florian.fainelli@broadcom.com>
References: <20250625231053.1134589-1-florian.fainelli@broadcom.com>
MIME-Version: 1.0
X-Original-Sender: florian.fainelli@broadcom.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@broadcom.com header.s=dkimrelay header.b=vDS0zxQ3;       spf=pass
 (google.com: domain of florian.fainelli@broadcom.com designates
 192.19.144.207 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com
X-Original-From: Florian Fainelli <florian.fainelli@broadcom.com>
Reply-To: Florian Fainelli <florian.fainelli@broadcom.com>
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

Include the GDB scripts file under scripts/gdb/linux/vfs.py under the
FILESYSTEMS (VFS and infrastructure) subsystem since it parses internal
data structures that depend upon that subsystem.

Signed-off-by: Florian Fainelli <florian.fainelli@broadcom.com>
---
 MAINTAINERS | 1 +
 1 file changed, 1 insertion(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index a90d926c90a0..a292012a3ff1 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -9290,6 +9290,7 @@ F:	include/uapi/linux/openat2.h
 F:	Documentation/driver-api/early-userspace/buffer-format.rst
 F:	init/do_mounts*
 F:	init/*initramfs*
+F:	scripts/gdb/linux/vfs.py
 
 FILESYSTEMS [EXPORTFS]
 M:	Chuck Lever <chuck.lever@oracle.com>
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250625231053.1134589-17-florian.fainelli%40broadcom.com.
