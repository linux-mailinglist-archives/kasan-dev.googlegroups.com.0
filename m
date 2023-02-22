Return-Path: <kasan-dev+bncBDTMJ55N44FBBSFQ3GPQMGQEXSTDTNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 039CC69FAA2
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Feb 2023 19:00:41 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id bi21-20020a05600c3d9500b003e836e354e0sf1765607wmb.5
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Feb 2023 10:00:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677088840; cv=pass;
        d=google.com; s=arc-20160816;
        b=QzdMjKdh3WMfdNH3HZZ/7+f0jISIGmhe4tDYVDyUo82g2yP/U7wuqlqg7yjTKRKmED
         HN1WyUqTzYoOjeJLBlvCZrzLfPReo2jwKhJouXUa52e7i7eU+zxx2FGWsml6ZLjul1fT
         OEmKSzdsjCoT7nw7k2tIjtcqxBbo1fC2MEhfNBjEATyykR37l3aFdI8tIr6B+iKYE7UW
         O+VmLE59ExEPnB9A02wORJBXVal0KyMF8KysRR8fx+YmP3xzU5onOTyjtBkZri/i/fAb
         nadVPGQluEto4Ih0qwwm0jLJpJxYjDaC8wNVFKgRIWj0th4FVzChAD0YCQAX9KR3cg5L
         vtuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=5A7ddsvej9ryvLmFLXlUHYpMb+tJAZ7VcIAb4sHm/ew=;
        b=j/HpwMV0p0LUC71QfQLTzsaQ0/jqmAhz0OalnhqZ+/1+QTfuQ4JS831ybnhRyZ5BM2
         GyatA2sqk43i7HohesnqU6QnpAb44YopqdO45DuaCpq7UbeZi7EXiAJzOxzTyQxBxWfa
         ZkyTX0M4B0A7IVXrUN33z+PbFXTkbd4iZCuM7CBDpo1+8aarxsw3l1vXQ+HWNWqbCXt3
         xSLXLuFZSY+tz8F5o5ZmD0MsnzwbRYDuUpkN+SVmKV0eWqfagmTfY8jh4z6l3QpXTfRS
         AZC2KOaY0WiI29yajAs65D8aZHq4scd1jYMU+1Ta4JHHFUySdMSWy1ZkybWgPaxXqlhE
         pCag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.128.52 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=5A7ddsvej9ryvLmFLXlUHYpMb+tJAZ7VcIAb4sHm/ew=;
        b=sZur/96HkBERqwYNPYJjZ7dG8LKRLwPDrq7EJpplEISG2HuSsXUCqPSch7kJpLnKJz
         6I0d74hNl+ygZAtVMJ4/GxScGbwz2i+HUhhJ73eaIw3fwNRcLpHH6P8kZzx3MXiJrzSD
         eW3MwZf77J4SjpuARS14+JuM+4cBVRf3PYb2xyREEowicmOHpvWn3C9UNUVDQ6hV56q/
         oQ1w+vXXSj/OgyPiH7RTp3QddCKkL8gu51RER5rs3ROhQcCGnarrDmupWnDupDS490hg
         AGtschmM6mrup35TXrZdlbu+yDoY73V0HCwO6b0a5PBqxV+f6LQdQ55UrtIug5JQ9BLL
         f4Sw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=5A7ddsvej9ryvLmFLXlUHYpMb+tJAZ7VcIAb4sHm/ew=;
        b=7sWu/UbsKZY0lOTE3f/NuWNRBh+IZZfIn5XvWnRZWKqYpmo7dvpS95jdMUFzi6Zr2F
         1OtzinpAHaBVGlXjywq/OpRupMYPOyQHFrc7FDyog/DgmQYmHcdMZ8q5bO50lrfwGEt6
         9eUNF7pErVemvPQGt00dw+8cNakxQHrBLlFrPl/5hkHuXc+L66Fj0egUOa5XBnTVUT7+
         BaYh/0YzA5las9lyauAbv3WJuEoOFpHTD2o50mYYzS9YykLcE5a61EaoWtTbjVD0Ya0e
         OEfgmpew1ons3ijCDKFdNu5FtaO3orgXAqFpkhnOsJmLrpGwMBt4zqcXH6dUlmiHYMZw
         N04A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXMmej9fm/qDBPcXlr8XYfrk3+2WcxhyAhNdC9BGuu7hQKo92uX
	WOfWou2rN6RbsDDpn+DmEEA=
X-Google-Smtp-Source: AK7set9I8acFbM80L38diWxfIS8FECbSKq4LuHiXE3F6Az8EuaUcF5EiaOK3BSmrUs+bqk89chxqYQ==
X-Received: by 2002:a5d:4751:0:b0:2c6:e91d:1220 with SMTP id o17-20020a5d4751000000b002c6e91d1220mr74775wrs.301.1677088840272;
        Wed, 22 Feb 2023 10:00:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a3d1:0:b0:2c5:953c:231b with SMTP id m17-20020adfa3d1000000b002c5953c231bls2899553wrb.0.-pod-prod-gmail;
 Wed, 22 Feb 2023 10:00:38 -0800 (PST)
X-Received: by 2002:adf:cd82:0:b0:2c7:cc8:84a6 with SMTP id q2-20020adfcd82000000b002c70cc884a6mr1836975wrj.31.1677088838900;
        Wed, 22 Feb 2023 10:00:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677088838; cv=none;
        d=google.com; s=arc-20160816;
        b=O7Z+VCCxDMdUjYsJoQPljMc05eAqcSZOXDOzZKGeL1jgEw+N0ZvUQTvI0Uvvs/facW
         aon20q2JaRRr/aXUAqYmk+5igYM+ColZEPq9pnDinFdFE8XphaDhx5K84xebs1L4tmje
         ownGGLGuRadd3440pCIZZvNwhO/G/EyP8f1Zl/YW2s4hov5q5EL0kBMyEOjFG4QsA+o5
         Gs6V7a+XSrgeLbua2abcDye6ezr/wUUY0GBEGaVFBeySZz7lc3lnpTZo+R+58gdDRSre
         rFoutrki/CSVC/j/xD8RIrRahJ9Ya36f+u+PPYweiApPoSXJa4HaoxjvMjnSdxmAkqLk
         x1cw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=pB8V6SnbhQl8mQXpiuOZR/SGgLZPL4Xx8Q+WzhCE+9Y=;
        b=cNuoVj9JmYc6IvYr16w1XsYBwY3KalOiNdVypm3Sl3hLqBwHU+bEtiUvhAcjGXf3d2
         nUzmLonSbSllRAVKu6mZiJy9EZmvAKLb+edsatUgCbHT1KwAYPZWme+VyrDM/HQLwIi8
         kkkH3rHFN6ErHWzv6U25yC/o3Dt3vMRC1rFaOjjc4PbX+wUEMS/hzmk1ifPXgr318SEe
         O7eiEP+lAVrPjfLCZNp7z6dgjLQd6nUe1A3fqrDM0gP51rH6+JPQEnZeGYrJ/VyzguFx
         ErgIF4C8QCo89GqCN9//ayKTlIV094UTLGmJvieJ0JHDdyksFumH0LQH+TSPq9pUEagX
         A/lg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.128.52 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
Received: from mail-wm1-f52.google.com (mail-wm1-f52.google.com. [209.85.128.52])
        by gmr-mx.google.com with ESMTPS id bu26-20020a056000079a00b002c56aba93edsi295099wrb.4.2023.02.22.10.00.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 22 Feb 2023 10:00:38 -0800 (PST)
Received-SPF: pass (google.com: domain of breno.debian@gmail.com designates 209.85.128.52 as permitted sender) client-ip=209.85.128.52;
Received: by mail-wm1-f52.google.com with SMTP id c18so1708453wmr.3
        for <kasan-dev@googlegroups.com>; Wed, 22 Feb 2023 10:00:38 -0800 (PST)
X-Received: by 2002:a05:600c:3c8e:b0:3db:1f68:28f with SMTP id bg14-20020a05600c3c8e00b003db1f68028fmr7097858wmb.24.1677088838291;
        Wed, 22 Feb 2023 10:00:38 -0800 (PST)
Received: from localhost (fwdproxy-cln-033.fbsv.net. [2a03:2880:31ff:21::face:b00c])
        by smtp.gmail.com with ESMTPSA id p13-20020a1c544d000000b003e208cec49bsm2554050wmi.3.2023.02.22.10.00.37
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 22 Feb 2023 10:00:37 -0800 (PST)
From: Breno Leitao <leitao@debian.org>
To: axboe@kernel.dk,
	asml.silence@gmail.com,
	io-uring@vger.kernel.org
Cc: linux-kernel@vger.kernel.org,
	gustavold@meta.com,
	leit@meta.com,
	kasan-dev@googlegroups.com,
	Breno Leitao <leit@fb.com>
Subject: [PATCH v2 0/2] io_uring: Add KASAN support for alloc caches
Date: Wed, 22 Feb 2023 10:00:33 -0800
Message-Id: <20230222180035.3226075-1-leitao@debian.org>
X-Mailer: git-send-email 2.30.2
MIME-Version: 1.0
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of breno.debian@gmail.com designates 209.85.128.52 as
 permitted sender) smtp.mailfrom=breno.debian@gmail.com
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

From: Breno Leitao <leit@fb.com>

This patchset enables KASAN for alloc cache buffers. These buffers are
used by apoll and netmsg code path. These buffers will now be poisoned
when not used, so, if randomly touched, a KASAN warning will pop up.

This patchset moves the alloc_cache from using double linked list to single
linked list, so, we do not need to touch the poisoned node when adding
or deleting a sibling node.

Changes from v1 to v2:
   * Get rid of an extra "struct io_wq_work_node" variable in
     io_alloc_cache_get() (suggested by Pavel Begunkov)
   * Removing assignement during "if" checks (suggested by Pavel Begunkov
     and Jens Axboe)
   * Do not use network structs if CONFIG_NET is disabled (as reported
     by kernel test robot)

Breno Leitao (2):
  io_uring: Move from hlist to io_wq_work_node
  io_uring: Add KASAN support for alloc_caches

 include/linux/io_uring_types.h |  2 +-
 io_uring/alloc_cache.h         | 35 +++++++++++++++++++---------------
 io_uring/io_uring.c            | 14 ++++++++++++--
 io_uring/net.c                 |  2 +-
 io_uring/net.h                 |  4 ----
 io_uring/poll.c                |  2 +-
 6 files changed, 35 insertions(+), 24 deletions(-)

-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230222180035.3226075-1-leitao%40debian.org.
