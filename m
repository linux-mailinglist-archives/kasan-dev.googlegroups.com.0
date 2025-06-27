Return-Path: <kasan-dev+bncBDP6DZOSRENBBWME7PBAMGQE46QF3OQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9650EAEBCD5
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Jun 2025 18:10:04 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id d2e1a72fcca58-740270e168asf2074372b3a.1
        for <lists+kasan-dev@lfdr.de>; Fri, 27 Jun 2025 09:10:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751040602; cv=pass;
        d=google.com; s=arc-20240605;
        b=Lmne/JlMP0Am55lpiYD46Du+1Dc1GwhxynJj0ELp7G1EaJzSNtwDy+XWLzPoSM60aH
         PjpskGYTKO4xGgdhmys/zTxLCJ2orOZRDTi3UvFrXbGPUTFvdf+3wSrPHHqsHXfk/+Fc
         ynP5jrkPNeW7/V9+t+hOXgPOF5PaAV5/X/JozFEywfxP4Y7jSeOH+pXsLaj6DMSo5UND
         reQZVWYF1L5PRmLleEzl2BUnyUz17Lvk3zAr0NB4dVzLbN7X0UDQqcGTd0VGbOVi+u20
         Zi7NiCNxlpADhNSny1OFbx+YXiC+Bb+ebK6lLqAN7+RFH4tRfmj/XVGNUv8V0bbbuizD
         P4Xw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=/MoO9NpDI0+vW0L34/0oGt16Qa0ksADX1BweAKmBP1g=;
        fh=5kch/zlxpOqVXKv7+fUAJozHDhoprutdjBzaKetZcc8=;
        b=ZIFR82kKuM3HLv+3M4jvVcBR6SgfPJ54LeqV41s6INtLc5/02UrrLOScL51fNQl3f7
         /pZQ1MbzfHXvzDiie2Q3s55b5/JBlS9lqllvcUW7Q4pXyhvWfz1KbXLc+Lhvd/QLwkHJ
         zdMoOn84eua+kzIknVszT3rxlkxGHD6Q4qISLFH8+pJRrdZ4fuAcpHIGNRw8oQljqPZg
         kGRNPKlwpBfGh8ZaRcj6SOkL5+4Frq5cDBZMqIb0wO6c4G1D5U3BbZo6BUrxRC91JqGm
         wpVkUvXhYFQo6DL0rGi1mq7kHAnFuuYf7VQBRje4RUPdKc+SuoZ4iqfZomdKeMAUSYHQ
         5oKQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=google header.b=grqNzKEf;
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751040602; x=1751645402; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/MoO9NpDI0+vW0L34/0oGt16Qa0ksADX1BweAKmBP1g=;
        b=s3uxZESU3YLXI3iyaJwXG8TwCXPP0zfUKqXsBdBecUkaZX+9u7YcWgkzfzNXekmLZg
         pkOaarR0xMIRoOAYhkiaztOHQkbuLKQn2LIZrauRmwArSyFrlKsmzYkJxFpmcpq1jPuy
         8KNZpZnha3yynp8/5p4SGG39L0BDiKndNdFQ7LjueL5qBb5m2pHJCBPcPcJW2y4X65UN
         L8LPadJ1ilIx8OZ3zh0nedPvg15rgyhnJL9u2et2CW0UXAIlPMWlI45Lm5iM/WPZ8D9u
         vPFwqewMUM7Yv9jUu21cGN4etX9QTXEMHuNpq6knhwWpBLjiNSTbleZw/1K/bnYFq2fw
         26DQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751040602; x=1751645402;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=/MoO9NpDI0+vW0L34/0oGt16Qa0ksADX1BweAKmBP1g=;
        b=ccIZZf//rLyusdSFjfxcIzf2gizWl7jQljzQ/le61PilhgJt6s1iMQ38aTMjHn0z73
         juWRluCbVFxHB16bVLNe7s8kT8VUhx/nsRifkCDv+VqxDTF4ZTxcqnFkpj4KFpGU5bBr
         /5GKkOhn4JBXfTXvIeEv+/wHpZ+y6t4XPGSTlr+VNAQvTj4VGEaC9e6JohhGzAE8gaLd
         +I2QSPvxwK1WXSoe1zCmQdK/mz5RKq0ELHwuoN3gUMxMBAlq1V6KBSQo9PGMnk+YT7wF
         V8YvTTHG5S5pwtost099emr5XTmGvAIT2KU38vOq9WVUZ2oKD5JWTz/M7MMvg96ToXFt
         AT7Q==
X-Forwarded-Encrypted: i=2; AJvYcCUa5wr9FjTxslJIHtF15jPA48Uosz59454CH1vIVfnW/znVZct+Z8hiLI+qe+sdY86rMzesww==@lfdr.de
X-Gm-Message-State: AOJu0YyO3vb9Z2V80quncnRPSn5+/t4toMnBFwhXOrJhAE6H+sFb0lAK
	8/xRA3EEN8DNzvO3j6ZHr7gHSKqQf4uTZcyAMItWDTpNlnWSdJq/XnJG
X-Google-Smtp-Source: AGHT+IFjmIMZFAYkPAOsR8YlIY1BA5p3izlVr4R+WRy7LIGIoEAoVLvXcJZQ40OD0cUAFEFcg2BicA==
X-Received: by 2002:a17:903:2c6:b0:235:e71e:a396 with SMTP id d9443c01a7336-23ac48878b5mr51244775ad.51.1751040601916;
        Fri, 27 Jun 2025 09:10:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfQXDczshesfc4BtLPGTsFKfq2hpIJqZElq9GnXn61AAA==
Received: by 2002:a17:903:a8d:b0:234:f1c0:68d1 with SMTP id
 d9443c01a7336-238a81d3338ls13821995ad.0.-pod-prod-02-us; Fri, 27 Jun 2025
 09:10:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWTl70nrh2EOXKtWA3h7Mdj2IAOhTRKunXX2xOaXtXIudx2dY9S1YIelE0uWqdxmbP3ueWrEelTrJ4=@googlegroups.com
X-Received: by 2002:a17:902:da89:b0:234:e8db:431d with SMTP id d9443c01a7336-23ac45c5b7amr43199495ad.20.1751040600245;
        Fri, 27 Jun 2025 09:10:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751040600; cv=none;
        d=google.com; s=arc-20240605;
        b=SDoOgdrVoFY6ArVo6EXp85Dx0BZbCnh9cJu3Hodwa5KSHZ7Np+TR1/0uZak+t4qRIh
         YW7NSl6Voud09WW5PGiB1RvoIj2Lg7i4Jm67GJNwC3vj4wBUGeAn7Fdl+yT7HcnYcy8f
         yi2lkos1EUx0P9eV01cDAhqr6+h49ugqRvmEAEFOSvlqzWzys5bXG/43DCQXXnU0hSH4
         62CMWBHXyNOlfW4EZCb+DoDNyqpZ6Nb4+qLf4ikkvTrsgn4bs3jpFlvpkCAIZnDJM2E0
         tWeZ72DwUSmWGAmwdlj6Jhe9Uy4pQFnCT6z0nP4BiRkRTH7cVfI0NB7F1HjR+voCkDG5
         d4gA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=6tajG5R3MCsrP/w0wwPMIBf3LF9dc2Wm7Uf1cjFJKdc=;
        fh=ijvFijpz1Sn9nF8IjX1cbb/6Hp6XzZz8uodY/hZksgg=;
        b=N52oI52xKHzol9E+XZjcgW3CgKf3Km2DXuG0O2mCVZHpaveM2TjfD1JDi4adU93LFH
         sjDSKDZIjqMyHPzJ4H+0JGs0YTfpk2lLBCVVt/YYMbBroNkfmzh0XcY/KvJ4yu/6EZzZ
         7+owTjJxV34AxilcGIFvovBzrA1tuYJVNZ2itB4PfgUNO6NOptyUDm/7OUZrIgmEkx1b
         7/c485pc89Bnqta3ZPFmS0DA57VCX3MWRdkhgyu6nJ7+YvuWPA/yFvCpLthfX+6FB0GD
         bV+rvxrYkeJxaDJ0ZyRpjVjTcM/jLeqqQeGcDVIIQR4DtuEgx9dnzc541Ph1mnjlMb31
         9OcQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=google header.b=grqNzKEf;
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x433.google.com (mail-pf1-x433.google.com. [2607:f8b0:4864:20::433])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-23acb36dde2si835945ad.10.2025.06.27.09.10.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 27 Jun 2025 09:10:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of florian.fainelli@broadcom.com designates 2607:f8b0:4864:20::433 as permitted sender) client-ip=2607:f8b0:4864:20::433;
Received: by mail-pf1-x433.google.com with SMTP id d2e1a72fcca58-739b3fe7ce8so2840608b3a.0
        for <kasan-dev@googlegroups.com>; Fri, 27 Jun 2025 09:10:00 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUqeJla57JYpJCKswzQm7WlxAlrGKD0YbJ0dXvfp4tUHdtiLzVwIqoJBkUUYPJ4JWiE5MiRUuLRELM=@googlegroups.com
X-Gm-Gg: ASbGncvjw6aQR4AxngZe+jV6Cau+0531OBMRM2rzAdc4Ra3D8CxxthJYqNtsFL88imy
	ioS+b1YFym+X9MZSHX4Qph2kR15mqx4JSNLu4Plmt3LKDLPjHrjr/nM1jtKespmwlMN9w3yH0QF
	qSkzmajSBwmnH79mW0wkKz4en3KHuUpOdUoOCXLAH9IFGdgxVZ9TxGBYZTh489CVAjcwIceSNAQ
	gXMIZUProaDsjNS8Mfwg8YWQpoBr9SoeZz9Cgf8vfVpjnu1zC+I1qnOXCs0J9VAqQvbWjYJkA0d
	4sAUtYKE8AtFLnSXD9i99KlCBgZd5OpGF1aIbqbJbMOq4vH6fjYWPdzi4ussofbCnsBsIMxtRoJ
	QAtVhg90+ICw0mqxNHK+Y7Kn1ug==
X-Received: by 2002:a17:902:f709:b0:235:779:edea with SMTP id d9443c01a7336-23ac465d24fmr64232725ad.38.1751040599657;
        Fri, 27 Jun 2025 09:09:59 -0700 (PDT)
Received: from [10.67.48.245] ([192.19.223.252])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-23acb2e1b3esm18966805ad.35.2025.06.27.09.09.54
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 27 Jun 2025 09:09:58 -0700 (PDT)
Message-ID: <cc36310a-c390-42f0-9c82-5b0236a9abfa@broadcom.com>
Date: Fri, 27 Jun 2025 09:09:53 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 00/16] MAINTAINERS: Include GDB scripts under their
 relevant subsystems
To: Jan Kara <jack@suse.cz>
Cc: "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 linux-kernel@vger.kernel.org, Jan Kiszka <jan.kiszka@siemens.com>,
 Kieran Bingham <kbingham@kernel.org>,
 Michael Turquette <mturquette@baylibre.com>, Stephen Boyd
 <sboyd@kernel.org>, Dennis Zhou <dennis@kernel.org>,
 Tejun Heo <tj@kernel.org>, Christoph Lameter <cl@gentwo.org>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 "Rafael J. Wysocki" <rafael@kernel.org>, Danilo Krummrich <dakr@kernel.org>,
 Petr Mladek <pmladek@suse.com>, Steven Rostedt <rostedt@goodmis.org>,
 John Ogness <john.ogness@linutronix.de>,
 Sergey Senozhatsky <senozhatsky@chromium.org>,
 Ulf Hansson <ulf.hansson@linaro.org>, Thomas Gleixner <tglx@linutronix.de>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Luis Chamberlain <mcgrof@kernel.org>, Petr Pavlu <petr.pavlu@suse.com>,
 Sami Tolvanen <samitolvanen@google.com>, Daniel Gomez
 <da.gomez@samsung.com>, Kent Overstreet <kent.overstreet@linux.dev>,
 Anna-Maria Behnsen <anna-maria@linutronix.de>,
 Frederic Weisbecker <frederic@kernel.org>,
 Alexander Viro <viro@zeniv.linux.org.uk>,
 Christian Brauner <brauner@kernel.org>, Uladzislau Rezki <urezki@gmail.com>,
 Matthew Wilcox <willy@infradead.org>,
 Kuan-Ying Lee <kuan-ying.lee@canonical.com>,
 Ilya Leoshkevich <iii@linux.ibm.com>, Etienne Buira <etienne.buira@free.fr>,
 Antonio Quartulli <antonio@mandelbit.com>, Illia Ostapyshyn
 <illia@yshyn.com>, "open list:COMMON CLK FRAMEWORK"
 <linux-clk@vger.kernel.org>,
 "open list:PER-CPU MEMORY ALLOCATOR" <linux-mm@kvack.org>,
 "open list:GENERIC PM DOMAINS" <linux-pm@vger.kernel.org>,
 "open list:KASAN" <kasan-dev@googlegroups.com>,
 "open list:MAPLE TREE" <maple-tree@lists.infradead.org>,
 "open list:MODULE SUPPORT" <linux-modules@vger.kernel.org>,
 "open list:PROC FILESYSTEM" <linux-fsdevel@vger.kernel.org>
References: <20250625231053.1134589-1-florian.fainelli@broadcom.com>
 <fynmrmsglw4liexcb37ykutf724lh7zbibilcjpysbmvgtkmes@mtjrfkve4av7>
 <c66deb8f-774e-4981-accf-4f507943e08c@broadcom.com>
 <iup2plrwgkxlnywm3imd2ctkbqzkckn4t3ho56kq4y4ykgzvbk@cefy6hl7yu6c>
Content-Language: en-US
From: "'Florian Fainelli' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=florian.fainelli@broadcom.com; keydata=
 xsBNBFPAG8ABCAC3EO02urEwipgbUNJ1r6oI2Vr/+uE389lSEShN2PmL3MVnzhViSAtrYxeT
 M0Txqn1tOWoIc4QUl6Ggqf5KP6FoRkCrgMMTnUAINsINYXK+3OLe7HjP10h2jDRX4Ajs4Ghs
 JrZOBru6rH0YrgAhr6O5gG7NE1jhly+EsOa2MpwOiXO4DE/YKZGuVe6Bh87WqmILs9KvnNrQ
 PcycQnYKTVpqE95d4M824M5cuRB6D1GrYovCsjA9uxo22kPdOoQRAu5gBBn3AdtALFyQj9DQ
 KQuc39/i/Kt6XLZ/RsBc6qLs+p+JnEuPJngTSfWvzGjpx0nkwCMi4yBb+xk7Hki4kEslABEB
 AAHNMEZsb3JpYW4gRmFpbmVsbGkgPGZsb3JpYW4uZmFpbmVsbGlAYnJvYWRjb20uY29tPsLB
 IQQQAQgAywUCZWl41AUJI+Jo+hcKAAG/SMv+fS3xUQWa0NryPuoRGjsA3SAUAAAAAAAWAAFr
 ZXktdXNhZ2UtbWFza0BwZ3AuY29tjDAUgAAAAAAgAAdwcmVmZXJyZWQtZW1haWwtZW5jb2Rp
 bmdAcGdwLmNvbXBncG1pbWUICwkIBwMCAQoFF4AAAAAZGGxkYXA6Ly9rZXlzLmJyb2FkY29t
 Lm5ldAUbAwAAAAMWAgEFHgEAAAAEFQgJChYhBNXZKpfnkVze1+R8aIExtcQpvGagAAoJEIEx
 tcQpvGagWPEH/2l0DNr9QkTwJUxOoP9wgHfmVhqc0ZlDsBFv91I3BbhGKI5UATbipKNqG13Z
 TsBrJHcrnCqnTRS+8n9/myOF0ng2A4YT0EJnayzHugXm+hrkO5O9UEPJ8a+0553VqyoFhHqA
 zjxj8fUu1px5cbb4R9G4UAySqyeLLeqnYLCKb4+GklGSBGsLMYvLmIDNYlkhMdnnzsSUAS61
 WJYW6jjnzMwuKJ0ZHv7xZvSHyhIsFRiYiEs44kiYjbUUMcXor/uLEuTIazGrE3MahuGdjpT2
 IOjoMiTsbMc0yfhHp6G/2E769oDXMVxCCbMVpA+LUtVIQEA+8Zr6mX0Yk4nDS7OiBlvOwE0E
 U8AbwQEIAKxr71oqe+0+MYCc7WafWEcpQHFUwvYLcdBoOnmJPxDwDRpvU5LhqSPvk/yJdh9k
 4xUDQu3rm1qIW2I9Puk5n/Jz/lZsqGw8T13DKyu8eMcvaA/irm9lX9El27DPHy/0qsxmxVmU
 pu9y9S+BmaMb2CM9IuyxMWEl9ruWFS2jAWh/R8CrdnL6+zLk60R7XGzmSJqF09vYNlJ6Bdbs
 MWDXkYWWP5Ub1ZJGNJQ4qT7g8IN0qXxzLQsmz6tbgLMEHYBGx80bBF8AkdThd6SLhreCN7Uh
 IR/5NXGqotAZao2xlDpJLuOMQtoH9WVNuuxQQZHVd8if+yp6yRJ5DAmIUt5CCPcAEQEAAcLB
 gQQYAQIBKwUCU8AbwgUbDAAAAMBdIAQZAQgABgUCU8AbwQAKCRCTYAaomC8PVQ0VCACWk3n+
 obFABEp5Rg6Qvspi9kWXcwCcfZV41OIYWhXMoc57ssjCand5noZi8bKg0bxw4qsg+9cNgZ3P
 N/DFWcNKcAT3Z2/4fTnJqdJS//YcEhlr8uGs+ZWFcqAPbteFCM4dGDRruo69IrHfyyQGx16s
 CcFlrN8vD066RKevFepb/ml7eYEdN5SRALyEdQMKeCSf3mectdoECEqdF/MWpfWIYQ1hEfdm
 C2Kztm+h3Nkt9ZQLqc3wsPJZmbD9T0c9Rphfypgw/SfTf2/CHoYVkKqwUIzI59itl5Lze+R5
 wDByhWHx2Ud2R7SudmT9XK1e0x7W7a5z11Q6vrzuED5nQvkhAAoJEIExtcQpvGagugcIAJd5
 EYe6KM6Y6RvI6TvHp+QgbU5dxvjqSiSvam0Ms3QrLidCtantcGT2Wz/2PlbZqkoJxMQc40rb
 fXa4xQSvJYj0GWpadrDJUvUu3LEsunDCxdWrmbmwGRKqZraV2oG7YEddmDqOe0Xm/NxeSobc
 MIlnaE6V0U8f5zNHB7Y46yJjjYT/Ds1TJo3pvwevDWPvv6rdBeV07D9s43frUS6xYd1uFxHC
 7dZYWJjZmyUf5evr1W1gCgwLXG0PEi9n3qmz1lelQ8lSocmvxBKtMbX/OKhAfuP/iIwnTsww
 95A2SaPiQZA51NywV8OFgsN0ITl2PlZ4Tp9hHERDe6nQCsNI/Us=
In-Reply-To: <iup2plrwgkxlnywm3imd2ctkbqzkckn4t3ho56kq4y4ykgzvbk@cefy6hl7yu6c>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: florian.fainelli@broadcom.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@broadcom.com header.s=google header.b=grqNzKEf;       spf=pass
 (google.com: domain of florian.fainelli@broadcom.com designates
 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Florian Fainelli <florian.fainelli@broadcom.com>
Reply-To: Florian Fainelli <florian.fainelli@broadcom.com>
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

On 6/27/25 00:55, Jan Kara wrote:
> On Thu 26-06-25 09:39:36, Florian Fainelli wrote:
>> On 6/26/25 09:17, Liam R. Howlett wrote:
>>> * Florian Fainelli <florian.fainelli@broadcom.com> [250625 19:13]:
>>>> Linux has a number of very useful GDB scripts under scripts/gdb/linux/*
>>>> that provide OS awareness for debuggers and allows for debugging of a
>>>> variety of data structures (lists, timers, radix tree, mapletree, etc.)
>>>> as well as subsystems (clocks, devices, classes, busses, etc.).
>>>>
>>>> These scripts are typically maintained in isolation from the subsystem
>>>> that they parse the data structures and symbols of, which can lead to
>>>> people playing catch up with fixing bugs or updating the script to work
>>>> with updates made to the internal APIs/objects etc. Here are some
>>>> recents examples:
>>>>
>>>> https://lore.kernel.org/all/20250601055027.3661480-1-tony.ambardar@gmail.com/
>>>> https://lore.kernel.org/all/20250619225105.320729-1-florian.fainelli@broadcom.com/
>>>> https://lore.kernel.org/all/20250625021020.1056930-1-florian.fainelli@broadcom.com/
>>>>
>>>> This patch series is intentionally split such that each subsystem
>>>> maintainer can decide whether to accept the extra
>>>> review/maintenance/guidance that can be offered when GDB scripts are
>>>> being updated or added.
>>>
>>> I don't see why you think it was okay to propose this in the way you
>>> have gone about it.  Looking at the mailing list, you've been around for
>>> a while.
>>
>> This should probably have been posted as RFC rather than PATCH, but as I
>> indicate in the cover letter this is broken down to allow maintainers like
>> yourself to accept/reject
>>
>>>
>>> The file you are telling me about seems to be extremely new and I needed
>>> to pull akpm/mm-new to discover where it came from.. because you never
>>> Cc'ed me on the file you are asking me to own.
>>
>> Yes, that file is very new indeed, and my bad for not copying you on it.
>>
>> I was not planning on burning an entire day worth of work to transition the
>> GDB scripts dumping the interrupt tree away from a radix tree to a maple
>> tree. All of which happens with the author of that conversion having
>> absolutely no idea that broke anything in the tree because very few people
>> know about the Python GDB scripts that Linux has. It is not pleasant to be
>> playing catch when it would have take maybe an extra couple hours for
>> someone intimately familiar with the maple tree to come up with a suitable
>> implementation replacement for mtree_load().
>>
>> So having done it felt like there is a maintenance void that needs to be
>> filled, hence this patch set.
> 
> I can see that it takes a lot of time to do a major update of a gdb
> debugging script after some refactoring like this. OTOH mandating some gdb
> scripts update is adding non-trivial amount of work to changes that are
> already hard enough to do as is. 

This really should have been posted as RFC, because I can see how 
posting this as PATCH would be seen as coercing maintainers into taking 
those GDB scripts under their umbrella.

> And the obvious question is what is the
> value? I've personally never used these gdb scripts and never felt a strong
> need for something like that. People have various debugging aids (like BPF
> scripts, gdb scripts, there's crash tool and drgn, and many more) lying
> around. 

Those are valuable tools in the tool box, but GDB scripts can work when 
your only debug tool accessible is JTAG for instance, I appreciate this 
is typically miles away from what most of the kernel community does, but 
this is quite typical and common in embedded systems. When you operate 
in that environment, having a decent amount of debugger awareness of 
what is being debugged is immensely valuable in saving time.

> I'm personally of an opinion that it is not a responsibility of
> the person doing refactoring to make life easier for them or even fixing
> them and I don't think that the fact that some debug aid is under
> scripts/gdb/ directory is making it more special. 

That is really the question that I am trying to get answered with this 
patch series. IMHO as a subsystem maintainer it is not fair to be 
completely oblivious to scripts that live in the source tree, even if 
you are not aware of those.

 > So at least as far as I'm> concerned (VFS, fsnotify and other 
filesystem related stuff) I don't plan
> on requiring updates to gdb scripts from people doing changes or otherwise
> actively maintain them.

vfs.py script is beyond trivial, the largest and most complicated IMHO 
is mapletree.py which had to be recently developed to continue to 
support parsing the interrupt descriptor tree in the kernel, I can 
maintain that one now that I know a lot more than I ever wished I knew 
about maple trees. So really the burden is not as big as it may seem but 
it's fair not to be taking on more work as a maintainer, I get that.

Thanks for your feedback!
-- 
Florian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cc36310a-c390-42f0-9c82-5b0236a9abfa%40broadcom.com.
