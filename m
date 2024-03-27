Return-Path: <kasan-dev+bncBC7M5BFO7YCRBVG6SGYAMGQELCOM2DQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5817B88EEE8
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Mar 2024 20:11:18 +0100 (CET)
Received: by mail-ot1-x33d.google.com with SMTP id 46e09a7af769-6e67641a9a9sf133812a34.3
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Mar 2024 12:11:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711566676; cv=pass;
        d=google.com; s=arc-20160816;
        b=rcoIPvcm4LuqudIWZ3BC6ZJ+8BBXK0npWv7SHufxs1LYr54Qs6TKiJ7dbaBfWvbFtd
         PpoH+WqTKlzFvTlgsKVU5ykpyC4h2FaLyakdiwzGCJRV0C4cgNugQd1zBiFbm9TgoswF
         wg6Ajyomfbyl0IqR4WuI1QYSTMc9aAAkVMmhQ4HJNPUKY2MQtGNv+CpVHzIduWl4LGls
         P8l0iMCjFYp5DdXOyvK4arcauVwN88VlYxGHCiHfptkq7usCcvmAoV0FG7VP3T2t9giw
         fYp9qDgwV4Z4xaAczx6LzTWAYZzOQpePcB3RxrPD1BxM7glZG9tUum9Dl0kFvSbodj+X
         ke5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=u5R+33CQjcouA9X6MjaGCBbTOhB7jJLGlwB9TDWMwL4=;
        fh=AMUDA+moc5ymJ3WLKUjuq0AneMX6jJxkLRAvLE5mCSg=;
        b=eq5V9lXDTAM2dMFQsNdZAltluTtWrFDb6ruNJ0CN9SCvUGai9jKJPCTYr/Eyw/D3x4
         jhAf0AISGikEbljOKsEuUZP5GwHnMHc6fFIIlkJlruS0of2dhjlaHsAfwnM42ChHlxnc
         zscuxkfMlltdjvdTXfZ4EQikFEQ6GgaxOoY+CR2zKYknN2GJtCYKV1B/PU+zIpYN8etM
         fxQjaBMjI5OpR1eZ3U3kp8frTzPxm0/+ij6VnW1MP+LUh8Q8y+rWB4OnweqJ9p5FIu91
         IPgJID47sSOJZ0KIlQwWIdWUMYK++jHgFV0p/K/CfKMPPrU1kvEFuxq4BTBJAP3ovmA+
         1iiA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=gpMAFcrt;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=groeck7@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1711566676; x=1712171476; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-disposition:mime-version:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=u5R+33CQjcouA9X6MjaGCBbTOhB7jJLGlwB9TDWMwL4=;
        b=GandK+EBANDNMZ+fsIp8dX5G6O/MkkL/UxPKOUuyenLkilMfgqGYOmqvr/QXvrqsn5
         AKslOAhBttJflBzbZd6TZqjVoQiAIZ8locrBzz/Bn+khc04X0eWs1RDmE5e0MZ2Ci6HZ
         sy3UN6E4HnGrDCSDnddJCdgUPUm+SMdeBIhEPfIB/Trq9GOD3mdCSdXfqVNU72F3qZKL
         hHBFnfDpwY5nGRyeFSI6JuTGpgXHb/IAblFOCYp+Ple8OyfN/IRS/iNL/5ypzZzU0Iqb
         BxoKQ7vpsuuKRXtWOGUMhjnIhczg/vFFDxz/C5V5XinFj0wWK2d0+gIe9eg6HFaAfxtN
         J/Ig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711566676; x=1712171476;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :sender:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=u5R+33CQjcouA9X6MjaGCBbTOhB7jJLGlwB9TDWMwL4=;
        b=QMRgrJNP+sgcKUJ76UJPgKPf35mTY9tAAO0Y/OWZckxp3hsD26GZh6EdmjJ8XdZpKa
         UW4/Wl33HW6Qa8mBq8W78WK4JTav3+A+emMdPmXyKNMOG2drR7DNhk141ZJw2qWP+IDT
         M2I8ixogixpezVBKfIge1hj0J5oW63tiXk77uxsGJoNreeYPsJNCoP73236dXkoQRC4P
         qfHp+yop5RTB8Z+ta6bbu56v1ioms6zxAGUuGoY/fFQXxLGepqEpbIpLowQQuvmoybf9
         yzbaTDEcxWt+vpLTK2Dwi2nB9H+rRRZiC4rTCl1LMjZIPPMdZz8aDnJw6GsQJsFBPVMf
         hMhA==
X-Forwarded-Encrypted: i=2; AJvYcCV3Ka09K64cK00oMecM5jesOygPujadwPI/iyVLMZXUW26IteL9eOvEYFUHLcTqdtxD4Nds4dBExzR/l8USElJYVU+RSMiRaQ==
X-Gm-Message-State: AOJu0YzANps1fE7Zt6dpMP+yx9S3MOPgYl/vf94fjFMOksAxO4lUGNX5
	eHP5/OZsm5mN4TGYgy/SCw02CjpuVPRKHHVDA7yGwJekADi3PxbC
X-Google-Smtp-Source: AGHT+IHDJXCPC1RsBiS23ImL5x/bnaVmfBWf1uE6cAGwvBM7SyV3ZmPWdtL1zvqky0Jx4hAN/vR7Eg==
X-Received: by 2002:a05:6808:a0a:b0:3c3:e3ef:9809 with SMTP id n10-20020a0568080a0a00b003c3e3ef9809mr819970oij.16.1711566676634;
        Wed, 27 Mar 2024 12:11:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:1303:b0:696:b16a:600f with SMTP id
 pn3-20020a056214130300b00696b16a600fls237974qvb.2.-pod-prod-07-us; Wed, 27
 Mar 2024 12:11:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV/ycSXRUPKO486fc4vDeWl7BxpKR4QYAzwNVbYLnxB9ILCcsfxlGf242dgFMWH6BCbvST5W0TGPIZMjOvbjnaKPG8m/L55eTqOPA==
X-Received: by 2002:a67:bc06:0:b0:475:111d:c0dc with SMTP id t6-20020a67bc06000000b00475111dc0dcmr929321vsn.14.1711566675278;
        Wed, 27 Mar 2024 12:11:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711566675; cv=none;
        d=google.com; s=arc-20160816;
        b=HIpMgFXl743j8eLstlzKjc6Ka8K0zhx0oRqpDTPh69QSbedNOEs2UwsM9NXfPGvl8g
         l2AB11gdu4GWDOI67Q1etgnMXX/s4cH7Du/2UV7+0HnGechLSHatCiSF/JLUW2SpsurM
         hibWHkvNTVpupgp4/0n2NWNlVgmMLpXFIJXoNPRA1n3UcYrT7S6aSB4CawMDXop2VCEj
         h4dmswBhgJVYsiwSFsAKmC32ly+U2yyvCqzpefao8gdFu1SNyqTp1xCQfQJddThad8YN
         4A/esKvXZeXSmhdZ+7lRQ3Irv/XfSk7w+6sCPnjGM6VL4tFtS0WqqZ3KOEvfWtf61kO+
         jEzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:mime-version:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=4NMdyhQ5KQf+5t3j22eJ7oXRafJFy4NN7UKLX5AVnPI=;
        fh=fMplYIG9E7iQIkLm2CymNp/15GePmzfbAaH/Gu0J35Y=;
        b=d67Lg5pyzWj4vysEvAfD8lfuS9vzI2sQ/Xu91GlZhr8f5KXGsNpij+EtwFcn/elg52
         dQ18DcJf3V+dJebcIf6yjTtRdg7DNWbPh1RWzA5C1mTFAhAX0joxyIZS9Jm+4SOP/ClJ
         2c6q9msV9LQyDSXRGftK5o//CxTNViwrM8OPQhmI4Rvxa9cWrHevp+osOoSB27R1dx/a
         JrCJT86dhaUARlOeftwg+yVtC7zTi/ewRnIrsuhNlh1PZrUGZXX3H95fOopcPMSwdvit
         d2ABPRRS9lCt91jKkOl5yZc0IFCpTbBEjJg1gIEtbcP3dc8ewXVbGBt0FO4nB3wfPtvY
         rJYw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=gpMAFcrt;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=groeck7@gmail.com
Received: from mail-pl1-x633.google.com (mail-pl1-x633.google.com. [2607:f8b0:4864:20::633])
        by gmr-mx.google.com with ESMTPS id c3-20020a67c403000000b0047309ffd6fesi812011vsk.2.2024.03.27.12.11.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 Mar 2024 12:11:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) client-ip=2607:f8b0:4864:20::633;
Received: by mail-pl1-x633.google.com with SMTP id d9443c01a7336-1e00d1e13acso1483405ad.0
        for <kasan-dev@googlegroups.com>; Wed, 27 Mar 2024 12:11:15 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUJgbh31vhhg1qjahOPVulQjmZ1X8Xf7onRTF97GwZI0ii3mIG/gmfOXRT/huMZrdLhYotViJJD/sctC/HvFw8s9RRNdI5supj65Q==
X-Received: by 2002:a17:902:c083:b0:1e0:1a1f:5e4 with SMTP id j3-20020a170902c08300b001e01a1f05e4mr430245pld.55.1711566674587;
        Wed, 27 Mar 2024 12:11:14 -0700 (PDT)
Received: from server.roeck-us.net ([2600:1700:e321:62f0:329c:23ff:fee3:9d7c])
        by smtp.gmail.com with ESMTPSA id mo12-20020a1709030a8c00b001db717d2dbbsm9446567plb.210.2024.03.27.12.11.13
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Mar 2024 12:11:13 -0700 (PDT)
Sender: Guenter Roeck <groeck7@gmail.com>
Date: Wed, 27 Mar 2024 12:11:12 -0700
From: Guenter Roeck <linux@roeck-us.net>
To: loongarch@lists.linux.dev
Cc: Huacai Chen <chenhuacai@kernel.org>, WANG Xuerui <kernel@xen0n.name>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com
Subject: Kernel BUG with loongarch and CONFIG_KFENCE and CONFIG_DEBUG_SG
Message-ID: <c352829b-ed75-4ffd-af6e-0ea754e1bf3d@roeck-us.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: linux@roeck-us.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=gpMAFcrt;       spf=pass
 (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::633 as
 permitted sender) smtp.mailfrom=groeck7@gmail.com
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

Hi,

when enabling both CONFIG_KFENCE and CONFIG_DEBUG_SG, I get the following
backtraces when running loongarch images in qemu.

[    2.496257] kernel BUG at include/linux/scatterlist.h:187!
...
[    2.501925] Call Trace:
[    2.501950] [<9000000004ad59c4>] sg_init_one+0xac/0xc0
[    2.502204] [<9000000004a438f8>] do_test_kpp+0x278/0x6e4
[    2.502353] [<9000000004a43dd4>] alg_test_kpp+0x70/0xf4
[    2.502494] [<9000000004a41b48>] alg_test+0x128/0x690
[    2.502631] [<9000000004a3d898>] cryptomgr_test+0x20/0x40
[    2.502775] [<90000000041b4508>] kthread+0x138/0x158
[    2.502912] [<9000000004161c48>] ret_from_kernel_thread+0xc/0xa4

The backtrace is always similar but not exactly the same. It is always
triggered from cryptomgr_test, but not always from the same test.

Analysis shows that with CONFIG_KFENCE active, the address returned from
kmalloc() and friends is not always below vm_map_base. It is allocated by
kfence_alloc() which at least sometimes seems to get its memory from an
address space above vm_map_base. This causes virt_addr_valid() to return
false for the affected objects.

I have only seen this if CONFIG_DEBUG_SG is enabled because sg_set_buf()
otherwise does not call virt_addr_valid(), but I found that many memory
allocation calls return addresses above vm_map_base, making this a
potential problem when running loongarch images with CONFIG_KFENCE enabled
whenever some code calls virt_addr_valid().

I don't know how to solve the problem, but I did notice that virt_to_page()
does handle situations with addr >= vm_map_base. Maybe a similar solution
would be possible for virt_addr_valid().

Thanks,
Guenter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c352829b-ed75-4ffd-af6e-0ea754e1bf3d%40roeck-us.net.
