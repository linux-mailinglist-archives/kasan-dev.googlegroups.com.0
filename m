Return-Path: <kasan-dev+bncBAABBV54Z3FAMGQE5UG7TWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 921C5CE93DC
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Dec 2025 10:41:45 +0100 (CET)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-34ac814f308sf22419968a91.3
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Dec 2025 01:41:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767087704; cv=pass;
        d=google.com; s=arc-20240605;
        b=CIwMEFMlsKCLwmyP+Dhajb4URDljqZXTTnyE2f1W66TIIkKaWa+FmNGpgQM2lnYo5T
         s5bAcKyeNzw3tZFMW3qgAWV97xXKAo4tW6bBzG+CpXMS0HEjpzl0d4tLGh0IlYouGK/i
         n/4kQHyxJY9hCLiItn6uQW16gyBfolm5K9r1es4aA0v5y63iYNlsn3tL6Ykfiik1Xnh7
         7xOsJoChAI+nAbQSoJm2Wb+e3BCEip7DJnhzbzDsCdjwQcxeSXwiijzM3Vpr4iInGHgd
         PXC31Z4iPc0eyXGyqCaMdb+tv/vqO9D4wLRxPuUCK3oT1fpjxkPJ+BPSP5oeqwwRUT+Z
         WTkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=ZpnAvQOx9of0gcSDimgyTIX4eF5Be0Ae5uoAr7HlVHw=;
        fh=QCSAa8H3UkIQVUe+zpmxTr+ctDQappaYn+iMQMgJbxc=;
        b=klNApzzPiWaYW60so/mKHMt/vkN0ep85KBNIkSZRnmPhqBNHU//yeAl51NeuOpmuzx
         rAeCxkAApVdzMNZG/SldZPnE4lI65a8sTN6dvEvJMu5TeZMF4LRJeJl+MXABGGUxmfG4
         4wXMoD+aVt4Fwq9LqyFpZZ4E3Xo3SpIbS8XdaOkx1bwnfDtnwErHooBmm/ZyadCYKWGp
         c5dT5tCl7YNs4liVqcxOZKg0SHtyPMSTyqrXLjy4GGlTTaiWQQ6QbTQkjlJKuO2UzRGe
         kLzRhoPFljytOgF7LRFwrs9pJmBI0c/XftpAytdyqLQJ62OJyiuVl71vG4YWxufByGmC
         X9FA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of xukuohai@huaweicloud.com designates 45.249.212.56 as permitted sender) smtp.mailfrom=xukuohai@huaweicloud.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767087704; x=1767692504; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ZpnAvQOx9of0gcSDimgyTIX4eF5Be0Ae5uoAr7HlVHw=;
        b=JUqH2KJ/iNkV7sSrd5aMex4jYOQYdr6ZweFaqHiFQZVk6jmfevqho7NyDT+rUHLoiS
         Hdjuc2DAiRJugtvQr6sESkE+sNkf7CUQ8wX+bYVqMwjlDi5oWm4yGmyEi+WjiqCpIUAA
         TDiN0WdUsIsTx8v4Jx3LvM+43xsKtJs2beBpcR9NgwCy14MuXUOzitUSzmTCgtazb131
         sUF5nja6polswqFnMZqSIrma77yElbkosn94PQtHH6/bEt0IPbGKjl1A1e/xwuSAzi++
         GG7Ve7nqO+Dj0WbqeNaPbftZowka5vpBFr7+xcqCwh7L0tJbBEZD6hfJoVxVHzHL+tf8
         Xc4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767087704; x=1767692504;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ZpnAvQOx9of0gcSDimgyTIX4eF5Be0Ae5uoAr7HlVHw=;
        b=nsmBm8ZDw+aJXr5DCeiFKSnfSsav7txzV+YW3ZpeHCXqofWSpbSvEFr5mcCuCd56sj
         W2scELDR5TJJGm5ldaOhFIDil257dAowZAwkQjGzJIxntwACcRjLzjSULYYO8ShfVr+7
         art/lshSlACW0qQFveMW8aq0U6mNqLu0XNQju9DH0HBfoTyrUkQriGzYLKB1yR4LWUHB
         XCOhD74+n/U4Hf6In3G+/3PJrXy2gUFk0bY5qQicjVHIt8Lg+NdQw4Dr0EbIkY7bvpUk
         Yj5LAOO6675Em+R3EoDygvyJsLLNKtsIZoP6X9A5HeLmYEsUdaPdwtNfuXUsJjhndDJU
         ofxA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWmjjHnqYHAB6ry6b+pRLhwf7uZROqbJPck/V6asO1gMJNbhS2AlNG2ncNzfVoIind8bHVDFw==@lfdr.de
X-Gm-Message-State: AOJu0YxjbdDvMiB6QHIbNaqHCCmj6cB7ADrkVQOxiYKZbpWTMlOgI1xc
	3LLe/jKguC54g5dq0jNbxuvNJ6RYxMKnphOdDZdudYesGLp+tZ0PVs+w
X-Google-Smtp-Source: AGHT+IF6Bpl6i+fTdgyI3SZof7mHAjuccXhTylg9QTjo0eOBj33A+NFxPjjsB2oSRy0ct7rrT8I0QA==
X-Received: by 2002:a17:90b:3015:b0:34a:b4a2:f0c8 with SMTP id 98e67ed59e1d1-34e921ccb4cmr20574285a91.30.1767087703612;
        Tue, 30 Dec 2025 01:41:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYOcSbTgGTnaEuP0nV0m0BC+tMs4P2gijDSlXTMJ7YCOg=="
Received: by 2002:a05:6a00:1988:b0:7a4:b41c:6e3f with SMTP id
 d2e1a72fcca58-80b97ececeals2030264b3a.0.-pod-prod-08-us; Tue, 30 Dec 2025
 01:41:42 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXxnolD4gET+uFCG7sZ0yKfPpTnuSHI6GFRN9rQFOtaesWaVhMleBYhCSAcgqiB4ouWlAKXbtRYQg8=@googlegroups.com
X-Received: by 2002:a05:6a00:8014:b0:7aa:e5f2:617d with SMTP id d2e1a72fcca58-7ff651c3519mr31597643b3a.30.1767087702285;
        Tue, 30 Dec 2025 01:41:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767087702; cv=none;
        d=google.com; s=arc-20240605;
        b=g67f6wGCtDNxvpt0eRMQ9zFXvD4+4MOkdXkP1m3lYeH0OfGTGjaEvVXv3tXu7dwBeq
         LORzHjhcA+7PHBA7XNPeSIUqAJWCwZNmh7x9GUq8TV9BUFID17CrQCd69m9/N27+w8Oy
         NvACVvuMqqMfTbwxjlYdHPUejfJ8YlTkdlqHGhYQ3YfyC+ab6E1d904tYKRzlc6B5DXb
         YOfPF8rbcno9FnvQC5uhRVv4eWiHX4s4bMpG2i08+P/tTvmqjOb+gXrl5tooTBI14ShJ
         7cYHsLgNFfMcRIDkFqhgHx9u1+g/baLZ06lGUtlp+38qxA6I/ryJoYg6ky6tGL+q7s0C
         04gQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=B0r+O9YiNdWgUscH2a/GSABYlfKEPre75pSvsVvBMRw=;
        fh=gMFyD/zSKxfyivq0+sNdcixS30XUULxcgd1+86gO0Ic=;
        b=REffTBn2xHN9j1hJOK9oiH1M4GcQAlxFtuKD5rjRXqiOh+Sm+dvxea5feuRYvYWikR
         AiMFUSqAxeorEZlk/tQ2UZ3aUrPvTCYOVfT16Oi92SH7HnX9kKbxT7/elygvHVSbPFWw
         zDUrj+rrh1mBLX5GPHZ8SOdAhh6rAQrZwt8Rl52Sa7v72bSOGpdIVljZj46hScMeNU4V
         6zeAbruEb8qiqJKvZmjsd8SqAB4DyC0z5tBbUbVqzeLqQJA0uBMrRxHaeIHrY8J3PdT4
         y1AcuLh3YaV6ptTBxVZyMhIvUUe8FOUIl6xtYn5gU4J8etTeqBqW86Nei3UZkiaFDseH
         IkPw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of xukuohai@huaweicloud.com designates 45.249.212.56 as permitted sender) smtp.mailfrom=xukuohai@huaweicloud.com
Received: from dggsgout12.his.huawei.com (dggsgout12.his.huawei.com. [45.249.212.56])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7ff7cfdba52si1081220b3a.7.2025.12.30.01.41.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 30 Dec 2025 01:41:42 -0800 (PST)
Received-SPF: pass (google.com: domain of xukuohai@huaweicloud.com designates 45.249.212.56 as permitted sender) client-ip=45.249.212.56;
Received: from mail.maildlp.com (unknown [172.19.163.177])
	by dggsgout12.his.huawei.com (SkyGuard) with ESMTPS id 4dgSl916BhzKHMS1
	for <kasan-dev@googlegroups.com>; Tue, 30 Dec 2025 17:41:09 +0800 (CST)
Received: from mail02.huawei.com (unknown [10.116.40.75])
	by mail.maildlp.com (Postfix) with ESMTP id F26E64058D
	for <kasan-dev@googlegroups.com>; Tue, 30 Dec 2025 17:41:37 +0800 (CST)
Received: from [10.67.111.192] (unknown [10.67.111.192])
	by APP2 (Coremail) with SMTP id Syh0CgBXcYBNnlNpAr7tBw--.22205S2;
	Tue, 30 Dec 2025 17:41:34 +0800 (CST)
Message-ID: <d2c23a07-7072-4f10-856c-dab02e3ed15c@huaweicloud.com>
Date: Tue, 30 Dec 2025 17:41:33 +0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [QUESTION] KASAN: invalid-access in
 bpf_patch_insn_data+0x22c/0x2f0
To: Jeongho Choi <jh1012.choi@samsung.com>, bpf@vger.kernel.org,
 kasan-dev@googlegroups.com
Cc: joonki.min@samsung.com, hajun.sung@samsung.com
References: <CGME20251229105858epcas2p26c433715e7955d20072e72964e83c3e7@epcas2p2.samsung.com>
 <20251229110431.GA2243991@tiffany>
Content-Language: en-US
From: Xu Kuohai <xukuohai@huaweicloud.com>
In-Reply-To: <20251229110431.GA2243991@tiffany>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-CM-TRANSID: Syh0CgBXcYBNnlNpAr7tBw--.22205S2
X-Coremail-Antispam: 1UD129KBjvJXoWxZw4ftryUur43AF1xZr1rtFb_yoW7Jw43pr
	1qk34Ikw4kJ3y5uw4av3ZrCw12va1a93W3Gr4xJ3yFqr13Zrn3JF15tFy8Jr13u34qkr13
	AryDKr1aqryUZaUanT9S1TB71UUUUU7qnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUUylb4IE77IF4wAFF20E14v26r1j6r4UM7CY07I20VC2zVCF04k2
	6cxKx2IYs7xG6rWj6s0DM7CIcVAFz4kK6r1j6r18M28lY4IEw2IIxxk0rwA2F7IY1VAKz4
	vEj48ve4kI8wA2z4x0Y4vE2Ix0cI8IcVAFwI0_tr0E3s1l84ACjcxK6xIIjxv20xvEc7Cj
	xVAFwI0_Gr1j6F4UJwA2z4x0Y4vEx4A2jsIE14v26rxl6s0DM28EF7xvwVC2z280aVCY1x
	0267AKxVW0oVCq3wAS0I0E0xvYzxvE52x082IY62kv0487Mc02F40EFcxC0VAKzVAqx4xG
	6I80ewAv7VC0I7IYx2IY67AKxVWUJVWUGwAv7VC2z280aVAFwI0_Jr0_Gr1lOx8S6xCaFV
	Cjc4AY6r1j6r4UM4x0Y48IcVAKI48JMxkF7I0En4kS14v26r126r1DMxAIw28IcxkI7VAK
	I48JMxC20s026xCaFVCjc4AY6r1j6r4UMI8I3I0E5I8CrVAFwI0_Jr0_Jr4lx2IqxVCjr7
	xvwVAFwI0_JrI_JrWlx4CE17CEb7AF67AKxVWUAVWUtwCIc40Y0x0EwIxGrwCI42IY6xII
	jxv20xvE14v26r1j6r1xMIIF0xvE2Ix0cI8IcVCY1x0267AKxVWUJVW8JwCI42IY6xAIw2
	0EY4v20xvaj40_Jr0_JF4lIxAIcVC2z280aVAFwI0_Jr0_Gr1lIxAIcVC2z280aVCY1x02
	67AKxVWUJVW8JbIYCTnIWIevJa73UjIFyTuYvjxU7IJmUUUUU
X-CM-SenderInfo: 50xn30hkdlqx5xdzvxpfor3voofrz/
X-Original-Sender: xukuohai@huaweicloud.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of xukuohai@huaweicloud.com designates 45.249.212.56 as
 permitted sender) smtp.mailfrom=xukuohai@huaweicloud.com
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

On 12/29/2025 7:05 PM, Jeongho Choi wrote:
> Hello
> I'm jeongho Choi from samsung System LSI.
> I'm developing kernel BSP for exynos SoC.
> 
> I'm asking a question because I've recently been experiencing
> issues after enable SW KASAN in Android17 kernel 6.18 environment.
> 
> Context:
>   - Kernel version: v6.18
>   - Architecture: ARM64
> 
> Question:
> When SW tag KASAN is enabled, we got kernel crash from bpf/verifier.
> I found that it occurred only from 6.18, not 6.12 LTS we're working on.
> 
> After some tests, I found that the device is booted when 2 commits are reverted.
> 
> bpf: potential double-free of env->insn_aux_data
> https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=b13448dd64e27752fad252cec7da1a50ab9f0b6f
> 
> bpf: use realloc in bpf_patch_insn_data
> https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=77620d1267392b1a34bfc437d2adea3006f95865
> 
> ==================================================================
> [   79.419177] [4:     netbpfload:  825] BUG: KASAN: invalid-access in bpf_patch_insn_data+0x22c/0x2f0
> [   79.419415] [4:     netbpfload:  825] Write of size 27896 at addr 25ffffc08e6314d0 by task netbpfload/825
> [   79.419984] [4:     netbpfload:  825] Pointer tag: [25], memory tag: [fa]
> [   79.425193] [4:     netbpfload:  825]
> [   79.427365] [4:     netbpfload:  825] CPU: 4 UID: 0 PID: 825 Comm: netbpfload Tainted: G           OE       6.18.0-rc6-android17-0-gd28deb424356-4k #1 PREEMPT  92293e52a7788dc6ec1b9dff6625aaee925f3475
> [   79.427374] [4:     netbpfload:  825] Tainted: [O]=OOT_MODULE, [E]=UNSIGNED_MODULE
> [   79.427378] [4:     netbpfload:  825] Hardware name: Samsung ERD9965 board based on S5E9965 (DT)
> [   79.427382] [4:     netbpfload:  825] Call trace:
> [   79.427385] [4:     netbpfload:  825]  show_stack+0x18/0x28 (C)
> [   79.427394] [4:     netbpfload:  825]  __dump_stack+0x28/0x3c
> [   79.427401] [4:     netbpfload:  825]  dump_stack_lvl+0x7c/0xa8
> [   79.427407] [4:     netbpfload:  825]  print_address_description+0x7c/0x20c
> [   79.427414] [4:     netbpfload:  825]  print_report+0x70/0x8c
> [   79.427421] [4:     netbpfload:  825]  kasan_report+0xb4/0x114
> [   79.427427] [4:     netbpfload:  825]  kasan_check_range+0x94/0xa0
> [   79.427432] [4:     netbpfload:  825]  __asan_memmove+0x54/0x88
> [   79.427437] [4:     netbpfload:  825]  bpf_patch_insn_data+0x22c/0x2f0
> [   79.427442] [4:     netbpfload:  825]  bpf_check+0x2b44/0x8c34
> [   79.427449] [4:     netbpfload:  825]  bpf_prog_load+0x8dc/0x990
> [   79.427453] [4:     netbpfload:  825]  __sys_bpf+0x300/0x4c8
> [   79.427458] [4:     netbpfload:  825]  __arm64_sys_bpf+0x48/0x64
> [   79.427465] [4:     netbpfload:  825]  invoke_syscall+0x6c/0x13c
> [   79.427471] [4:     netbpfload:  825]  el0_svc_common+0xf8/0x138
> [   79.427478] [4:     netbpfload:  825]  do_el0_svc+0x30/0x40
> [   79.427484] [4:     netbpfload:  825]  el0_svc+0x38/0x8c
> [   79.427491] [4:     netbpfload:  825]  el0t_64_sync_handler+0x68/0xdc
> [   79.427497] [4:     netbpfload:  825]  el0t_64_sync+0x1b8/0x1bc
> [   79.427502] [4:     netbpfload:  825]
> [   79.545586] [4:     netbpfload:  825] The buggy address belongs to a 8-page vmalloc region starting at 0x25ffffc08e631000 allocated at bpf_patch_insn_data+0x8c/0x2f0
> [   79.558777] [4:     netbpfload:  825] The buggy address belongs to the physical page:
> [   79.565029] [4:     netbpfload:  825] page: refcount:1 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x8b308b
> [   79.573710] [4:     netbpfload:  825] memcg:c6ffff882d1d6402
> [   79.577791] [4:     netbpfload:  825] flags: 0x6f80000000000000(zone=1|kasantag=0xbe)
> [   79.584042] [4:     netbpfload:  825] raw: 6f80000000000000 0000000000000000 dead000000000122 0000000000000000
> [   79.592460] [4:     netbpfload:  825] raw: 0000000000000000 0000000000000000 00000001ffffffff c6ffff882d1d6402
> [   79.600877] [4:     netbpfload:  825] page dumped because: kasan: bad access detected
> [   79.607126] [4:     netbpfload:  825]
> [   79.609296] [4:     netbpfload:  825] Memory state around the buggy address:
> [   79.614766] [4:     netbpfload:  825]  ffffffc08e637f00: 25 25 25 25 25 25 25 25 25 25 25 25 25 25 25 25
> [   79.622665] [4:     netbpfload:  825]  ffffffc08e638000: 25 25 25 25 25 25 25 25 25 25 25 25 25 25 25 25
> [   79.630562] [4:     netbpfload:  825] >ffffffc08e638100: 25 25 25 25 25 25 25 fa fa fa fa fa fa fe fe fe
> [   79.638463] [4:     netbpfload:  825]                                         ^
> [   79.644190] [4:     netbpfload:  825]  ffffffc08e638200: fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe
> [   79.652089] [4:     netbpfload:  825]  ffffffc08e638300: fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe
> [   79.659987] [4:     netbpfload:  825] ==================================================================
> 

Seems it is the same as the second issue fixed by the following patch:
https://lore.kernel.org/all/3f851f7704ab8468530f384b901b22cdef94aa43.1765978969.git.m.wieczorretman@pm.me

> I have a question about the above phenomenon.
> Thanks,
> Jeongho Choi
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d2c23a07-7072-4f10-856c-dab02e3ed15c%40huaweicloud.com.
