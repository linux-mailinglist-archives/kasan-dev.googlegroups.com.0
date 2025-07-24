Return-Path: <kasan-dev+bncBDP6DZOSRENBBLWKRLCAMGQE7CMO5OQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id B09A4B11317
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Jul 2025 23:27:11 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id 3f1490d57ef6-e72ecef490dsf2154967276.0
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Jul 2025 14:27:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753392430; cv=pass;
        d=google.com; s=arc-20240605;
        b=fBS86OQL72AwZivhkVvNNL95C+MANW2yHPqV1yNgDRydrbBYhXSWLe8c6YDB14vH27
         at3KF4aM0sYJOkbPqcwwqaGDEi2e7nYWSo3xiPSnijme2ht1rjqYR+F8msLTXx78WTHx
         m+1qlK09gx9qo/zdMoK5CvYJcWYPETrkkkGAlm8YXOqeVbOpBTSL2VSqZydmMI6kUwxz
         1TbcaV+ALeNYaCLZOFT8aDGI96iRMl8gSdd2jBtjjLqHQGuKV3wbQL+LWKldY+ChDByD
         bZ41jHnc7DXNo+aJ4ug7J/FBadtQnklDo5OVB1lkBro+4NJMfKx4ZJstYrPP7ltQJJms
         t1gQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:autocrypt:from:content-language:references:cc:to
         :subject:user-agent:mime-version:date:message-id:dkim-signature;
        bh=FQ5YGuvnNvjdCf2ztxzBg9BhosrH3WHIqFRL4FaF+tU=;
        fh=q32FQN20aIVq7n09rBjwZR/za7poEmskrIf1kQi6XlA=;
        b=detU1HqeB+8vBW7yP2tMm+TgoCj+ahd9E85+wDzm3XEb5SQxZED/Ro6He6bMthzF7d
         OcIunm0oeEShQZIAcYuL62nftQpwof8NO3EHVyip2+scURqUncfrWJeWeOf5TRCbrDuN
         O6PkaWgNtlsJpgs04Vzy1tHwvKwb249CDTBSPjFqGeQy+pv/IHTpJHXX6Edi7gwoMC9u
         L6M4Lc+grye2Jy/Q0vHpUEhVKyLu/T6fPkv+TqGiu6KUjX1bXs28z8Bd+WXozHuHcRb2
         WEzpoaub2B9S2bvGW92Ljbgiwql6z8T4wjE9DHHEv1rWoPhN36ltsuwN5rM+6r5Ib9UE
         nBxQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=google header.b=K8vRyPVB;
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753392430; x=1753997230; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=FQ5YGuvnNvjdCf2ztxzBg9BhosrH3WHIqFRL4FaF+tU=;
        b=V6GXiXZqb83PpOXP4xxvE8+DVZh3ZOwnSfcsn68oaOCyHQeIyp7JgRUXk8XAJzGQdS
         KfyyCvUUpDrw1kBTMGanOBHd1ollhxGbUvypnysgrKlZliTj4vRMwz7LK5WdlEu6P8XH
         frcYnxElT5OeqZx/zNo/7lhLqaFDbFcO9iTFsr4jcgpkXxN33FChTJko+kMrzcSay9DF
         AoDM9wnj5vFzr9K8lEnnxVQNb9lyeMKwDlYg9VjKvHomqT6JWf3cXHg1rq6N+/hkx2WF
         G2OpW0P5wV097mGFulN6eqDdHTtez5J49MFn6d1HuHTCtl9KRPHEu+lZjcbHBCpa7JON
         WJ/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753392430; x=1753997230;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:x-beenthere:x-gm-message-state:from:to:cc:subject
         :date:message-id:reply-to;
        bh=FQ5YGuvnNvjdCf2ztxzBg9BhosrH3WHIqFRL4FaF+tU=;
        b=c8M8C0rFMHSnL6x3oBmCF+5Ws+Ld9oitdfurG4Lf/aUwNuNc3SXeNY1OyeRnRn9ai9
         r8OW5tOz37AzYhYrcmg6vwvoogmJkyYCHEGNJ43doNYDPllEvinbyF6Pph37JyaPN+9q
         +FReIw9ml3j1alux59umnd5n/mLaoo4ubNHtiFkji8jAhs/OHs1wVggU1NLoGqf6hbEK
         m/GoVxePl5MSfngL1Gvy503NAC1MnDcPhkso4ZTKlmmsO2i7B2plK9CCj5lW++ivUg4q
         bFSYv/hQ/NwYH0WU9zbLxB7UHjnNi5vDygn1/Zvw+Uam9pw1knUgg9DpH3YjNaQ3/3kw
         vbGA==
X-Forwarded-Encrypted: i=2; AJvYcCWh2FJzPJvNMr9L1p6juqfiPN3JaG6UMuJ7stUiYSdLNu3PZuGwKmxfNwzMHoBWpWJVF/NiuA==@lfdr.de
X-Gm-Message-State: AOJu0YyXzFtQ1aaGIabexjBbMyFiQtM9K4GvVQSsED3JMGl+N8VIv6L3
	hJhN9XDCS3WWGOC2pH7EjbSMYm/WKaLdwqVfFbEfrz/5UNtGo8nxpxGb
X-Google-Smtp-Source: AGHT+IFR1ADjXRV0uJmX0Ed1dhy7v27BzPbAlYi0gfbTdfGEqLZnl8IHhYYyqHHWC0z+/xD5uFpE2A==
X-Received: by 2002:a05:6902:220d:b0:e87:a0a3:841a with SMTP id 3f1490d57ef6-e8dc5829c92mr10406937276.19.1753392430198;
        Thu, 24 Jul 2025 14:27:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfOEf+DaXXzNy2edQOxYhu16kpyuEqR3TMH6tKI9ASa9A==
Received: by 2002:a25:dc93:0:b0:e8b:c77e:c82b with SMTP id 3f1490d57ef6-e8ddc2d0d7dls1580591276.2.-pod-prod-04-us;
 Thu, 24 Jul 2025 14:27:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWhOqtI8Dxa7dt3wAwIm1uppvXncW+VuWEIjFbfOTY+KUD3pk0fm32vENd/HGxWHwEeuCjgHlvfxKU=@googlegroups.com
X-Received: by 2002:a05:690c:fc8:b0:719:7e82:e26b with SMTP id 00721157ae682-719b433cbbdmr123468037b3.35.1753392429224;
        Thu, 24 Jul 2025 14:27:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753392429; cv=none;
        d=google.com; s=arc-20240605;
        b=KvxdNLDCF3Jrose/sVqJwrISqnKiHto//OqlGdEaquZAo44uC0ak5+SQwNgBO7dUHY
         f+kHnNjLBMpOV20sgXpYqd4q/JzF/aydMiQN+V3aE+fWmUJyVCIa8VfUxlvexuYyDSyB
         sBoQ1oO8K6ohARdqRHaIGr0GZGzNtjtEG2izc1N+QgcHd80dPqIbjuo06QKR+X+6cRGL
         2BpmS2CCq1Pn0CZeE6zqRe0AAPWCjBYjcYdQxka9RXxWb9fu0aIqWbvZVBkkmWOmOLVj
         YrVIdqvrXL87JWDVDHQfO+RDttEHpnb6sGLV2y52NqXMjZGnceeoktFRVa/rN7w3Lgs+
         QO4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=BrQZvefTT8J72h8dUnTdsjaXor2WmZQIMIJXwY4LKOg=;
        fh=s1tP3UHQJ1uN69uiJFMPrlt8xpMt0PpW2bIK44PCxrM=;
        b=VznXjm3pXzr8a5DvcDYs0I5iV7R1oud7/aJKWVdOMcFAi/M4vHZKAqsUi+yEuwXiJ6
         gNKD9oWO6VMWwVf3yn5Ncqp3IhW9fNGsCkE2sD8hGGl+kAuL6CfzHNtzD73LlY9bBp/V
         G3jjBP3wH4PPMHgr4vif2KBt/PzWvCZ9ZaDN8YpW6kPiRbp17ZtCWkAhPmodHCEGwd/h
         Qo1W2f6RhSBHTUaFShegxuPniNGC1IDUMepNx/rxxMLj1RhF0DSRLBD0M2xVqKSkfPbN
         muD+2wZGfGgz6nTo+TWNeRTEVNbhzLu2RG0H7GEseDsfPi4wB1/RcwwFwgKemw0r2Frc
         ABdQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@broadcom.com header.s=google header.b=K8vRyPVB;
       spf=pass (google.com: domain of florian.fainelli@broadcom.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=broadcom.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf36.google.com (mail-qv1-xf36.google.com. [2607:f8b0:4864:20::f36])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-719cb906718si1231567b3.4.2025.07.24.14.27.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Jul 2025 14:27:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of florian.fainelli@broadcom.com designates 2607:f8b0:4864:20::f36 as permitted sender) client-ip=2607:f8b0:4864:20::f36;
Received: by mail-qv1-xf36.google.com with SMTP id 6a1803df08f44-700c7e4c048so21362496d6.3
        for <kasan-dev@googlegroups.com>; Thu, 24 Jul 2025 14:27:09 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXOf8t/3gDiCF55UcSUK7UqPaCRgA5K1IOscx/LwTzayQaZtPboxSHY6NchOXCcc5pnGGlBCpvQygU=@googlegroups.com
X-Gm-Gg: ASbGncvk3fYGeFU7t/6tm3GUyYWk4cczTPVCzIl3qHHlqMh6/Kzf/UQCzkti9fd2tgt
	3+U1UZ8TThYnUKhhLIeGF0iT5/pV7VmHtiUH8LIXfykpUqzR0fvAhqjSoalD9tA6LDPoWljSKPA
	bimP/T92FiBJ6qwSZFhrSNZipaANwohztsgdV41dXipj/4elogjGOrnegt4xRtEdL8Hudz9Wj8x
	YrlIvyD9Jzo/LVw4MklYyzSq6nmaKEZ8w0WSg607r0J+lDhP91247U0aICoqALqntxuDbv3IhmJ
	t6xnac8u6ptsUSJ8/C7k/sGF6BbUdsveGd064FhFanbE9kWhWLDzZtXAbCvUJOXU3n7NaMrJHhx
	5NwHZ9+fICXqPCUkNlmmcI3pEyIF5AswCpPYWv7kTs2G7EmIjH6nuIvsz2yziTA==
X-Received: by 2002:a05:6214:c22:b0:706:ea6d:e161 with SMTP id 6a1803df08f44-707007167e0mr108054966d6.32.1753392428572;
        Thu, 24 Jul 2025 14:27:08 -0700 (PDT)
Received: from [10.67.48.245] ([192.19.223.252])
        by smtp.gmail.com with ESMTPSA id 6a1803df08f44-7070fc9d5e3sm18704486d6.53.2025.07.24.14.27.02
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Jul 2025 14:27:07 -0700 (PDT)
Message-ID: <f084e692-7fd5-417c-8e49-860c2ce47d33@broadcom.com>
Date: Thu, 24 Jul 2025 14:27:02 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 08/16] MAINTAINERS: Include GDB scripts under MEMORY
 MANAGEMENT entry
To: David Hildenbrand <david@redhat.com>, linux-kernel@vger.kernel.org
Cc: Jan Kiszka <jan.kiszka@siemens.com>, Kieran Bingham
 <kbingham@kernel.org>, Michael Turquette <mturquette@baylibre.com>,
 Stephen Boyd <sboyd@kernel.org>, Dennis Zhou <dennis@kernel.org>,
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
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Luis Chamberlain <mcgrof@kernel.org>, Petr Pavlu <petr.pavlu@suse.com>,
 Sami Tolvanen <samitolvanen@google.com>, Daniel Gomez
 <da.gomez@samsung.com>, Kent Overstreet <kent.overstreet@linux.dev>,
 Anna-Maria Behnsen <anna-maria@linutronix.de>,
 Frederic Weisbecker <frederic@kernel.org>,
 Alexander Viro <viro@zeniv.linux.org.uk>,
 Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>,
 Uladzislau Rezki <urezki@gmail.com>, Matthew Wilcox <willy@infradead.org>,
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
 <20250625231053.1134589-9-florian.fainelli@broadcom.com>
 <04116d0f-2815-4583-853e-e4295fb3d014@redhat.com>
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
In-Reply-To: <04116d0f-2815-4583-853e-e4295fb3d014@redhat.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: florian.fainelli@broadcom.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@broadcom.com header.s=google header.b=K8vRyPVB;       spf=pass
 (google.com: domain of florian.fainelli@broadcom.com designates
 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=florian.fainelli@broadcom.com;
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

On 6/27/25 10:10, David Hildenbrand wrote:
> On 26.06.25 01:10, Florian Fainelli wrote:
>> Include the GDB scripts file under scripts/gdb/linux/ that deal with
>> memory mamagenement code under the MEMORY MANAGEMENT subsystem since
>> they parses internal data structures that depend upon that subsystem.
>>
>> Signed-off-by: Florian Fainelli <florian.fainelli@broadcom.com>
>> ---
>> =C2=A0 MAINTAINERS | 4 ++++
>> =C2=A0 1 file changed, 4 insertions(+)
>>
>> diff --git a/MAINTAINERS b/MAINTAINERS
>> index cad5d613cab0..52b37196d024 100644
>> --- a/MAINTAINERS
>> +++ b/MAINTAINERS
>> @@ -15812,6 +15812,10 @@ F:=C2=A0=C2=A0=C2=A0 include/linux/mmu_notifier=
.h
>> =C2=A0 F:=C2=A0=C2=A0=C2=A0 include/linux/pagewalk.h
>> =C2=A0 F:=C2=A0=C2=A0=C2=A0 include/trace/events/ksm.h
>> =C2=A0 F:=C2=A0=C2=A0=C2=A0 mm/
>> +F:=C2=A0=C2=A0=C2=A0 scripts/gdb/linux/mm.py
>> +F:=C2=A0=C2=A0=C2=A0 scripts/gdb/linux/page_owner.py
>> +F:=C2=A0=C2=A0=C2=A0 scripts/gdb/linux/pgtable.py
>> +F:=C2=A0=C2=A0=C2=A0 scripts/gdb/linux/slab.py
>=20
> Probably they should go to the corresponding sub-sections. At least=20
> slab.py?
>=20

Sounds good, thanks!

--=20
Florian

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/f=
084e692-7fd5-417c-8e49-860c2ce47d33%40broadcom.com.
