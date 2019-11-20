Return-Path: <kasan-dev+bncBCF5XGNWYQBRBI5D2LXAKGQEAX7DHSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3d.google.com (mail-vk1-xa3d.google.com [IPv6:2607:f8b0:4864:20::a3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 349771030EF
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 02:06:45 +0100 (CET)
Received: by mail-vk1-xa3d.google.com with SMTP id 131sf10621284vkb.11
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 17:06:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574212004; cv=pass;
        d=google.com; s=arc-20160816;
        b=PP4VQbKAeVprIJcwhzTIVeFb0US6DzkY8yp2V2uhWONuuiY3K0KMJRy7EkSOpMk1T0
         PXZSvMiP5qRvkV8opkE9fllXdX/HHueKtQKUOB7X6Ld/JyYg2jsER/I5+g1zJWzUst+T
         4ePFcHzjtJIrgmF933wqo6Atpln8odXfQgqFW4l5EJr12h5uq/Mafza9H+YljaPCTSAy
         tzYtgHYOdTmmgs/KgkrdrryNBnHZQ5sNvuiaehzbUHV72PNAk8cF1vfVuwiefyLGqheu
         Fry3m3tgvAeO8T3SUNgVXmiG+K9AUereL72BChloiI3qhKuGhpNFbYj6XzldSKulxUGp
         SJ/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:date:subject:cc:to:from
         :mime-version:sender:dkim-signature;
        bh=T2QT/sQeD2rz43o54EUDHtY9ZlibdwSBkZsschEMmmk=;
        b=nUafH6NH8E+v1aZjmcgT5KuU+uofI6i2pz/9sLwcuHTZd4CaNnVRD26gyn0Nx4yEet
         +h0YwbMyZ+aG2XgZq/Rgd3LPoB36gLZKhjEIiKHM9Cy1oSGWPugR6QRb1RZihqsTbcs5
         GL9FRArI62mh+DR/RXrWP8C+9KH8kv8n1GayAMkMOCsm7mj9RE38nDtnZU8CruJQNhEE
         UiyH3Gx1bGB8rNz95iqeG8hLYvfVQjiiYbp8yD4zW8aNCiqVk6pnRqOJWtAtRVqDZ37/
         9qXSi3Bg1BkRond+BEVMxc76rzLmwFT3U7e44/wqlfhjLWyi4UaQozueOEXaTtRmPI/N
         yyjQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=QPNZ3TFY;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=T2QT/sQeD2rz43o54EUDHtY9ZlibdwSBkZsschEMmmk=;
        b=gF605k89V2DDx2lmlISz6u8hGr73U2MSbV6q1PTQsFzEQaRIKu/dPrQqhYZ6KjktSv
         akpBPJu3xAlfF4r+37EF/BJp9rpQ8awmz1OHGVNrnmDuheyKIxBzjEE/YQZccNQYtP2J
         mL86YoDJQSuf8DQjw4kaWeSPeSkDnKq8558ZM6SHiO90XI4RhSKltvLSk8EWco/nF0En
         wnO0n+I4WvtY092hy6qQT1SzE4GPG7JcxNCFailH9NYuM+/3bBntwuG/uCBY+Dy2BXlB
         eaaw2oRM5xJm53eCSVXTyFcoBcEzpC7i0R09kz1Ed8KTNtaKiD3QbqHlWqTDfY2Zg1pv
         F+/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=T2QT/sQeD2rz43o54EUDHtY9ZlibdwSBkZsschEMmmk=;
        b=rgZcM1xkgFOyKsBWX/RVL/CBb5vJOqe8HDgzY2zwgqJEAW8yqja/hO8Q0w4PeoQDWm
         AcaBb8JAs5pj8rHrZGSsWzh3b8xrtf0H2tJX7Jpf0YlgEiVNPz1xKOeFcQqUwkgVFeC9
         8qUA+M9XrcM42bEiE6CLNVP4m4cD+DnZyCwR6oUJwuJvGPZy9ejn6DlRZ85xX7rtCxdC
         mPnFdd69u7faMxbb+bv3ypSFbNEtaE2zk41rZeRaRm0g+H84dsa8x9MEOEKW015cdC32
         QSI2hi+WDhRQEIXbkmzsiVEyHEQ36PR07cDKb5QqHRsi77JKgLP4ygEi5HfMHjt7nxGa
         eKMQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUScAAbR4zy3DglhyW4kRhIPjVj6Oc8un7u/5pOqa43UYXc5iQB
	Zsx2D6Yqh3pkotPDl3oaVlc=
X-Google-Smtp-Source: APXvYqzIVJD/Na4syRhpwwq/e+Djp+GGRZcYgdtZ0DYmB80hnlYQGRTB840B6GdYCT6ghMRfmkT++A==
X-Received: by 2002:ab0:74cd:: with SMTP id f13mr93661uaq.104.1574212003765;
        Tue, 19 Nov 2019 17:06:43 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:2bcd:: with SMTP id f13ls10523uaj.2.gmail; Tue, 19 Nov
 2019 17:06:43 -0800 (PST)
X-Received: by 2002:a9f:224b:: with SMTP id 69mr96324uad.108.1574212003415;
        Tue, 19 Nov 2019 17:06:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574212003; cv=none;
        d=google.com; s=arc-20160816;
        b=jR23YRgNi4Uvizzct+fCYC2dGa3h/HO1AXh0AkGu8YWwJMZ//QLmoQTrs9kupwzU7/
         ZnU7LYC/TbIsaXsLyeYqMJp0vrlHniFGabHS2R8n70YKJKPscN2DqZQn2zWACgdmsWvx
         n/gxmIoV6U6VKLVJNwzXWLCLuifLfbHLTxrZnx2jcjA/klF5QYoqFRDAsaNWgw3+miP+
         1YSsEWSJdqz4ei2IsYW69rjJSeRCJixzkLCV//af8pcD3Pzz+yUUvv/cZE9XW8AOkyQ8
         veWrbb7HDb4E8FPRyTYBaHBQWe9BoOgUBW/qvbJo6fViSe86EPXLzvjR2qLSXaCAocgw
         BykA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:date:subject:cc:to:from:dkim-signature;
        bh=CUFUdRWnKnM6bQsVtJfdZZf6wE8f8HKbQO0cl/4N/Js=;
        b=uWRlDCqqjymqT3BXPqtUyH3BfsIxux8Gb3ksC6ZfuEFKezQO4j4iMRCf92XqTMmbEX
         gz2KxGX5nG0SFhqlzjqOqgv8wF+FgG1BYRNizR7Ujl9jzz5vhrlcHTqoyKI29M5cLC4V
         AuZMu6J/Etq6JmdfhKvJ+TYVZ/Qui3aDM7GYvvquOV75X5l06moCTJnHqMilGEiydhmd
         FkNO7Qd7KmVD+rPe6+ju39STCDN/ox8fpz1BQz6htqBt1jUUUsTorPk5l5Hd4oNsmUSH
         MfyYUO+vV/YtLqni+CovBvtc8/WQWvRb+OyRKKYFONnQUopBPDajY/SPfiGO28FA+wY7
         Frgg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=QPNZ3TFY;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id e11si1348882uaf.0.2019.11.19.17.06.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Nov 2019 17:06:43 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id q26so13295713pfn.11
        for <kasan-dev@googlegroups.com>; Tue, 19 Nov 2019 17:06:43 -0800 (PST)
X-Received: by 2002:a62:ae17:: with SMTP id q23mr705132pff.2.1574212002529;
        Tue, 19 Nov 2019 17:06:42 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id k6sm24445726pfi.119.2019.11.19.17.06.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Nov 2019 17:06:41 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Kees Cook <keescook@chromium.org>,
	Elena Petrova <lenaptr@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	kernel-hardening@lists.openwall.com
Subject: [PATCH 0/3] ubsan: Split out bounds checker
Date: Tue, 19 Nov 2019 17:06:33 -0800
Message-Id: <20191120010636.27368-1-keescook@chromium.org>
X-Mailer: git-send-email 2.17.1
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=QPNZ3TFY;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::441
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

This splits out the bounds checker so it can be individually used. This
is expected to be enabled in Android and hopefully for syzbot. Includes
LKDTM tests for behavioral corner-cases.

-Kees

Kees Cook (3):
  ubsan: Add trap instrumentation option
  ubsan: Split "bounds" checker from other options
  lkdtm/bugs: Add arithmetic overflow and array bounds checks

 drivers/misc/lkdtm/bugs.c  | 75 ++++++++++++++++++++++++++++++++++++++
 drivers/misc/lkdtm/core.c  |  3 ++
 drivers/misc/lkdtm/lkdtm.h |  3 ++
 lib/Kconfig.ubsan          | 34 ++++++++++++++++-
 lib/Makefile               |  2 +
 scripts/Makefile.ubsan     | 16 ++++++--
 6 files changed, 128 insertions(+), 5 deletions(-)

-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191120010636.27368-1-keescook%40chromium.org.
