Return-Path: <kasan-dev+bncBDW2JDUY5AORBSHZ4WSQMGQEKUVR7BA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id E589375B6C4
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jul 2023 20:28:25 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-63c78bd1078sf9783196d6.1
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jul 2023 11:28:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689877704; cv=pass;
        d=google.com; s=arc-20160816;
        b=nPXyKEwEMk4taLfuYzXvxxPnAilQG/DIla9/QSm5SbIsUYTE0wl3yHbb353YTCQkhT
         HVC6s6WnJB8gIKWrxmXht8I21JVM/lUpODuKv8oiXu6Naa+26bZ++qHRYIeXeYUbB5gP
         qUOm6qCcwwCffUmoJYhY2L7g6Px/QngNg493i17/By53YxBl7ilfjqdyoUn5ZlYgFqDM
         F1ggkmhO+rpZlKZK1iy/68MhyF3myAQu4/TgYbFBWXVsZG3y1BO2Hg1aaoUoT1fvT/td
         PgCP+CybxS3kB61XNP/xH8xWSwEDsMbQCLQeYxUXa0cbRUDtsPZs3MFLKaxvwqanPgn7
         rvUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=qxN8rhGwew/CBx4eF9tr6Fr29858HPGk+YlJLuRzQVs=;
        fh=9ziCYI3mCjDLn+ojW0pVVXB/lSWssrGTJXwUBQsZb24=;
        b=KebSVBcMCk5mCChrZ725/As6aeKAznPMKHqg2LHqqB24bXL80SfVoQCm4saooD1PWN
         Smdquks+vH0LXGMgNa0KIL+iad9+jUwYmgiR2tHeoBB11FeEHTIgw8QzbyKwip+FqgLa
         qzXD18hCCT056rwthRphe+ddEuRsfHWvTBEucgWpppv4UId9iI1y7KnAwDH9gF2rDXIR
         6wYwwK0O02bIL3Cm7Pk98Mr5DXMrCjwR1x7UUensl8orM6CQZ1CT87QOZa3Tmf+lnMcS
         tausOd5NUV5Iik6jF5rEfLhQxQJl6YU3CykGAVb8rBZ2ecETQw1QlMp35mh9nOkWq/jf
         i/OQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=hqnI1dBb;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689877704; x=1690482504;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=qxN8rhGwew/CBx4eF9tr6Fr29858HPGk+YlJLuRzQVs=;
        b=OGfBLFbtBYHNGiYc7PMB0pCkWjbcdu7Ad4dt9ydopg2Cm0HgKL9Z+PIxIV+FipFdwd
         g977UOmEmo+awdlzRnTdBXDPQ0+Th3XJkBp9fQiVhjLhQzRkZwH4028fZf/Z1v3N0Nei
         ZRO7L70YOm/+/P0I+EGJ1ldAJXquef221nH4OHwy0u74DGHf49oO5zBXp5iUSHwuSeAv
         tbH/ViA5P50utfJ19kST6Vx7mQ985tGPituxjZ8Pc9IvIKtpD9HR0EQdjYqgnoRqYMKR
         MH/S2BIBUrmyvhREWY4BQHOZBAkCwefpz7IIWmL6N6Wx8kMQp1GxxwqZgSIo7gs+pcjL
         kwFg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1689877704; x=1690482504;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:mime-version
         :from:to:cc:subject:date:message-id:reply-to;
        bh=qxN8rhGwew/CBx4eF9tr6Fr29858HPGk+YlJLuRzQVs=;
        b=ng6lt/2m0g/Q07QNc9riWERNMGwCRThl5KzhA6WGFnTBuCi8RnVFjRpVJZ1VYC9GyT
         G56xOauagis0ZpuZlxEpBUBgZrQeju8rfcn77rtnvtvxdCZoQn6tpdvccZ+PKyviGENt
         4qYhADtlx3a8x6VUMbWtwgvuHH2IMq9bF85kLS2f4rhKhmNTVSGnvyYxBnG7yGlsU9dh
         Q27EywRkShZSDFQZYy7NPWX19vh3Xy99295KbeL4iUUHAJ2f349WlkWo7wU86jYMuq7D
         soSba3Py5KqZ/lgq71TqyGQoW7TfIQUi+UIDC9i6PLwBJsDZgPDe9cZm06XEBIxcPJhf
         Bh0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689877704; x=1690482504;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=qxN8rhGwew/CBx4eF9tr6Fr29858HPGk+YlJLuRzQVs=;
        b=WHPwljKRX0EAbnowZe+XJAYRhXLCY0EjOVVmphxqaPW3BVdodDI6WQYRKYGlmiXLb2
         MyMfc3zVTemMIm47d0D5zwhK3Lb8kk4eBZkwJvlCkXgKba4K2kkoXQPEJd4vxHByJell
         rz6liqlZW2Q29E4Zpsr6H5mjg+0qde0k9djL5D2ad7IDq8W34TfxH4hiZsTz7amp0+Q6
         d22WnWNkjw7RaDSQSIr0xBnK8iN0wMQ1ovz7/w7cgbVTKPwV31Yfyj2Y1kI9LX8JZjY2
         6SSGNAzgnWMeNT2vgOaDU6s2x9EH6rPAZe6+A1lMQw2g+qUHsN9F7B++dRs6hjK8vap0
         Tcpw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLZZCK3bQ/gdvMYkPbVxDvkO+Zzr8Gtpj1umACr4pq3FecrK+BbC
	8+23cxgWtLS73s8tQ3isI6s=
X-Google-Smtp-Source: APBJJlFavXFHrU5SQa1+VfXCV3AGfDcJ0Qmq2vSpfDrjD/o5HAcNRPFEKpQzG4T/dF1P4/M4fWgwvQ==
X-Received: by 2002:a0c:f4d3:0:b0:635:e286:d4b with SMTP id o19-20020a0cf4d3000000b00635e2860d4bmr6877809qvm.18.1689877704671;
        Thu, 20 Jul 2023 11:28:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:8e8d:0:b0:635:a666:7535 with SMTP id x13-20020a0c8e8d000000b00635a6667535ls906422qvb.2.-pod-prod-00-us;
 Thu, 20 Jul 2023 11:28:24 -0700 (PDT)
X-Received: by 2002:a0c:db0a:0:b0:61b:65f4:2a15 with SMTP id d10-20020a0cdb0a000000b0061b65f42a15mr7207181qvk.12.1689877703983;
        Thu, 20 Jul 2023 11:28:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689877703; cv=none;
        d=google.com; s=arc-20160816;
        b=BZBA1L3rK9/JR54jxjQwfXM8nnD70jfoAqAVQkWDkF3B+2yuzcjq4Qv9WfNGPoHLDW
         fW3EN261qgjWz6cmTFMSI3hY6gzI6TQa283oX/XWJtUHZ0Y0JaYef162vyaYAxTDbbaT
         cW/GBtkjieniAeKcNw+DxSC0lCuENrwbECyxnutuiDGzB2O88qUjgFyIBCe+OF6e0Vpa
         dGV+xEB0HBp8WM2ISrhek7q2LUNharOHImMDaBBsvnC9xokYhEkdQrHQQjCGqzjCmGPN
         COJo6dH08OFtJ/eCPGT1vvkeLw1YJMCsXG651txfBk6/QicP4kW0g34XOogwUBFkFjMS
         1Cow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=ewZhIVwE8fDX4FV/wESFHKZ+RXyFbSOKCfyrDW+WKpk=;
        fh=9ziCYI3mCjDLn+ojW0pVVXB/lSWssrGTJXwUBQsZb24=;
        b=fS0Eg6w0AKNOBIdJvmEIjPHTeg5UayOOWzznanwpbHKIF3qAgWZ2BHl8OSLdOe5QV4
         yUeqx2AkvRnlVkyVwPi/mEnuN/JnUadLhcP7jhu/xXIVns7PW5Ge2h6NYk/O9X6ZG3fg
         iWwii4iF9TxlwwrpTJKPiRSVzVQqG9Pg1RAdVQ20ofjhS5nNKTogy1ugV54KIAzdyW+I
         n0otOx4B5SVkjKvCpHOr+S7Gm11O4U5D2Qzlj+A4XsDweKQeAaNtBPsj4jQ5iCAlRiMP
         4K6hyelUDxfaC/x8y6VxL+KZXm6Gf+/iXgYPv/8qhA+wbCMBRuBOnDJKfTZyIzXLDx5z
         iLRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=hqnI1dBb;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x436.google.com (mail-pf1-x436.google.com. [2607:f8b0:4864:20::436])
        by gmr-mx.google.com with ESMTPS id on28-20020a056214449c00b0062dec72a6b6si122058qvb.1.2023.07.20.11.28.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Jul 2023 11:28:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::436 as permitted sender) client-ip=2607:f8b0:4864:20::436;
Received: by mail-pf1-x436.google.com with SMTP id d2e1a72fcca58-666edfc50deso801554b3a.0
        for <kasan-dev@googlegroups.com>; Thu, 20 Jul 2023 11:28:23 -0700 (PDT)
X-Received: by 2002:a17:902:d481:b0:1b9:e23b:bb6a with SMTP id
 c1-20020a170902d48100b001b9e23bbb6amr412561plg.11.1689877702909; Thu, 20 Jul
 2023 11:28:22 -0700 (PDT)
MIME-Version: 1.0
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 20 Jul 2023 20:28:12 +0200
Message-ID: <CA+fCnZdeMfx4Y-+tNcnDzNYj6fJ9pFMApLQD93csftCFV7zSow@mail.gmail.com>
Subject: MTE false-positive with shared userspace/kernel mapping
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Peter Collingbourne <pcc@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Alexander Potapenko <glider@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Florian Mayer <fmayer@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Willem de Bruijn <willemdebruijn.kernel@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=hqnI1dBb;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::436
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Hi Catalin,

Syzbot reported an issue originating from the packet sockets code [1],
but it seems to be an MTE false-positive with a shared
userspace/kernel mapping.

The problem is that mmap_region calls arch_validate_flags to check
VM_MTE_ALLOWED only after mapping memory for a non-anonymous mapping
via call_mmap().

What happens in the reproducer [2] is:

1. Userspace creates a packet socket and makes the kernel allocate the
backing memory for a shared mapping via alloc_one_pg_vec_page.
2. Userspace calls mmap _with PROT_MTE_ on a packet socket file descriptor.
3. mmap code sets VM_MTE via calc_vm_prot_bits(), as PROT_MTE has been provided.
3. mmap code calls the packet socket mmap handler packet_mmap via
call_mmap() (without checking VM_MTE_ALLOWED at this point).
4. Packet socket code uses vm_insert_page to map the memory allocated
in step #1 to the userspace area.
5. arm64 code resets memory tags for the backing memory via
vm_insert_page->...->__set_pte_at->mte_sync_tags(), as the memory is
MT_NORMAL_TAGGED due to VM_MTE.
6. Only now the mmap code checks VM_MTE_ALLOWED via
arch_validate_flags() and unmaps the area, but the memory tags have
already been reset.
5. The packet socket code accesses the area through its tagged kernel
address via __packet_get_status(), which leads to a tag mismatch.

I'm not sure what would be the best fix here. Moving
arch_validate_flags() before call_mmap() would be an option, but maybe
you have a better suggestion.

On a side note, I think the packet sockets code ought to use GFP_USER
and vmalloc_user for allocating the backing memory in
alloc_one_pg_vec_page, but that shouldn't make any difference to MTE.

Thanks!

[1] https://syzkaller.appspot.com/bug?extid=64b0f633159fde08e1f1
[2] https://syzkaller.appspot.com/text?tag=ReproC&x=17fd0aee280000

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdeMfx4Y-%2BtNcnDzNYj6fJ9pFMApLQD93csftCFV7zSow%40mail.gmail.com.
