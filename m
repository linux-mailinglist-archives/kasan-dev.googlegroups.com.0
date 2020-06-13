Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBHG7SP3QKGQE2HVLFKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id CE99F1F83E0
	for <lists+kasan-dev@lfdr.de>; Sat, 13 Jun 2020 17:24:13 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id n8sf10181371qtk.11
        for <lists+kasan-dev@lfdr.de>; Sat, 13 Jun 2020 08:24:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592061852; cv=pass;
        d=google.com; s=arc-20160816;
        b=qOaoJf7QZ5rz4lokBCY+n9DE3k6ZoF1Hp7oYQYbLcQ1YkPn6hNPcemf5R5OeJhDQAM
         32xJpQVcGwvQtgpTTx5NMyjbosIG6mjU3zMTARzKQTUDP4eJbm5TaqDeKgmG9PtGRQM5
         ncZeZ4y2LlMe7noxJQX+3x5b5QftLLZ3wIgAxPbG8mTZQP7nv68kuBO6cIqzm4ensBlj
         5RlMrw876xSxuwoxfZb/n1rVFpqgvqAJMODhCqQADziEShnc+OpSQW6jRPCS14KKej5h
         kLxHA56XFxzf8DkcEx2A23TM97QMIqm+YNYrlIHMvY5l0JC1k+B8+3RCWe9YvJVGj6uk
         dBPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=MUhZbQZa2a3Heyp+c6/zcLoTexBoXLxx/FnBQvE0gA0=;
        b=l6bla1rNgn25pEwoq6aif6aMgZa8K/9X7Efd3XM4rKVzATrrKXWMGV9xtdHxmJOmt4
         95H1rBUv34YpmebcMfVNIBTJ4iwjzhq/9wORPhUFdkwYXcu3i1qwcg4Tl8FGLfkdB141
         C0qvXYEbhLN2K9ZpPJaSIsm2qkrHzof9oxAfOPE1ximGDGE3BATkZCkY0UHOrc2vf00Y
         sxjhgYwZVgiNJdySk10tJxBzSTuaEvhh01aL6m38CD7WOlqDcamnm5otJfmTp3Lsayni
         l61cwQDez2AcbXWlTD0flWm+udnQAPa8G6sWfy50Y4jBOflQCoFxSnu+GU1XwNvHuQH8
         kbmw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=KN8SYt5Y;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:mime-version
         :content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=MUhZbQZa2a3Heyp+c6/zcLoTexBoXLxx/FnBQvE0gA0=;
        b=nMpDQKyglOARjmKBXmCI3/YubNqNlx831sSmvOmUYHc+D9GswK57WWKJKxHrWkNixg
         cXTbtop/4uiVqZJScA5lqBdw4x43HvtQuu3ji8vNeyrWie1w8YKKjDUyesn2hifvqYGw
         gx9yVXXBvK4cdpP2IqWLG/qPcwlDpvr99nmyqunoc1lrJPJA5M5NxE6sDei0ho+I+blv
         5W4yFGDULuZMQbFeHjhBNpO1p4oEoCV/FalWzIAC2S8gc296GZnt3BJiTgbQJjSz4bed
         ce6pF0cCg8EHX+ZAxSPbKU+tTVFWooIibgEnbxsZfWtEtC5c7IzEPHWpAO0LlayNFwcn
         sboA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :mime-version:content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MUhZbQZa2a3Heyp+c6/zcLoTexBoXLxx/FnBQvE0gA0=;
        b=h7j9Cvf26V6EOHopip07mcgem3H/lhEkVfi/urKkFb8YqmiOAElxcpo9zcQHOcE0x+
         5Lpn4JNpBXPBVdMu5UzlBzKSnsOCxHJfGS2FZyLB5O7kgkjhvejwfwcntvVmxnYHxeC6
         5sGWBIz4ZppnI+eSJnMCBmucheCrIm1pmOv6AmT5MIWUu4s4r5yjiY+/Wed36ZToRIFY
         neS3NAyMGkRxGz0ftRA6FuQBRO2xTlqCozdqKH/foAQuYkv5RZAHGSE/GXUqoACM4Wm8
         eRUmfzLNmeBnprdGHATUxrPTjQzFvcVSr1slgCB2g4SttD9MheOzb1G5DGnha1/SnmuE
         L0lg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531OoLasfKm0fqq7larSFZuKZ+WMx2Ks3wygDJxZ2F5tZJMUo/GG
	ND/QE4hxaFpwyMjfN+cSZx8=
X-Google-Smtp-Source: ABdhPJzi+0EW/yJgmahkDyXsAJWpbHEoN72C/8mQG2ja3bembwMqUNGYX51JJ+Z0P6iMOPzYAHmjgA==
X-Received: by 2002:a37:a08:: with SMTP id 8mr8022049qkk.388.1592061852689;
        Sat, 13 Jun 2020 08:24:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:524:: with SMTP id x4ls1991135qvw.11.gmail; Sat, 13
 Jun 2020 08:24:12 -0700 (PDT)
X-Received: by 2002:a0c:f1c7:: with SMTP id u7mr17786945qvl.181.1592061852373;
        Sat, 13 Jun 2020 08:24:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592061852; cv=none;
        d=google.com; s=arc-20160816;
        b=NPOnB29gvmzfjFz77/JyTv3B3IaKhcjNxYzMk0rM4/d0VJfiBXmuWROdI2c5ksyePd
         xYLNnVtLK3widi34hqfQeIwNqtNhjSxYfebr1OXYgpzfXiOzYQe4TIoh98p8UxYzqT79
         ARBQFJXARJc0o9bpJGLf7L4SW7zXKmEXMP5eshVgEyTuk4nY3nVBscJRPvZBOhGwUBiZ
         XpPsy0otz4FwGJNBTqQi3XzJqR41NzSUKDlmXQ5F+uZUPhnYddXTbBN+9JiCh+K/TglN
         rgASex8itqbT2aSX3LrFg/LDg+Xw7bNwjKPsR3VtpZeGb653kiZR5/s2e5qS+K6TLlen
         DQiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:mime-version:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=K+KNXh23H/lYi3GHCxbvjXtlx4d86Mx/AsR2sdZAOx0=;
        b=SHyL0r9eqy9JLHWhZFtAfJv+bPAuTogEb1/jLv60rZUlx7Aecyh7Jca3SYpt5ef0OC
         U+61yU7tcx/nCNvtNQ8FlgF8ZbAO7AHqtIeJaRNGyc92nB31fVe6Dq6TbXG0vzROcOL2
         xbdS3vSqtsDWzWLX/7cEPWLHtN5/ATmys5ec2ZrH4hSmtPsmwe2W5+pXQlHwONGVAjbz
         0kLYQI9qgAf0YJ6bSciwLB2EkqGKs/tTW0WvDcvjsSZcYN4M/FhUUlWWw4RaFYpOECsQ
         sQiAVUw9m4up4UA11ajXuHAJwkJL+kNnBg+1qa5LsRBrNHWgy6nlcxfAE9Uvz2hG65Hk
         a6LQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=KN8SYt5Y;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id z202si404674qka.6.2020.06.13.08.24.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 13 Jun 2020 08:24:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id w3so11847059qkb.6
        for <kasan-dev@googlegroups.com>; Sat, 13 Jun 2020 08:24:12 -0700 (PDT)
X-Received: by 2002:ae9:eb47:: with SMTP id b68mr7757837qkg.479.1592061851859;
        Sat, 13 Jun 2020 08:24:11 -0700 (PDT)
Received: from lca.pw (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id q187sm6895055qka.34.2020.06.13.08.24.10
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 13 Jun 2020 08:24:11 -0700 (PDT)
Date: Sat, 13 Jun 2020 11:24:08 -0400
From: Qian Cai <cai@lca.pw>
To: thomas.lendacky@amd.com, brijesh.singh@amd.com
Cc: tglx@linutronix.de, bp@suse.de, glider@google.com, peterz@infradead.org,
	dvyukov@google.com, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: AMD SME + KASAN = doom
Message-ID: <20200613152408.GB992@lca.pw>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=KN8SYt5Y;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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

CONFIG_AMD_MEM_ENCRYPT_ACTIVE_BY_DEFAULT=y + KASAN (inline) will reset
the host right away after those lines on linux-next (the mainline has
the same problem when I tested a while back, so it seems never work),

Wrong EFI loader signature.
early console in extract_kernel
input_data: 0x000000000c7ad3a8
input_len: 0x0000000000aa5f4c
output: 0x0000000001000000
output_len: 0x000000000c1808cc
kernel_total_size: 0x000000000b62c000
needed_size: 0x000000000c200000
trampoline_32bit: 0x000000000008a000
booted via startup_32()
Physical KASLR using RDRAND RDTSC...
Virtual KASLR using RDRAND RDTSC...

Decompressing Linux... Parsing ELF... Performing relocations... done.
Booting the kernel.

The .config (plus CONFIG_AMD_MEM_ENCRYPT_ACTIVE_BY_DEFAULT=y):
https://raw.githubusercontent.com/cailca/linux-mm/master/x86.config

Reproduced on several systems including,

HPE DL385 G10
AMD EPYC 7301 16-Core Processor

Dell PowerEdge R6415
AMD EPYC 7401P 24-Core Processor

Even on one of the HPE DL385 G10, it is able to boot but NO such
message, "AMD Secure Memory Encryption (SME) active"

Set KASAN=n will boot and has the above message at least on those Dell
systems.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200613152408.GB992%40lca.pw.
