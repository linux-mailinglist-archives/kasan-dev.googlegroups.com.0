Return-Path: <kasan-dev+bncBC32535MUICBB7725XDAMGQEZ5VLQWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id AB910BABB30
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Sep 2025 08:49:36 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-79a3c16b276sf97604976d6.0
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Sep 2025 23:49:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759214975; cv=pass;
        d=google.com; s=arc-20240605;
        b=areixS3CCCMD2ndMABGm90rUZvTFzUdcY1ezMgHkYcsxuf4gB47+XMJC2B5cdEcxJw
         QeI/3k6vf+fiKTHYI4JHdQswWJTd4oNX5osz4aT8+lqzsx+FaON/WoJdK6AswSoNNhQU
         Ict3AKNGqdHwhFRlBsw3rdLcLCiOhBYuo7VoNoy/mkMx7Qsm8k/uomOgt2TsHi2rqM6j
         m2f7v6/OGR40RU13cCT2WMlGw4h46bw2GBaLJaXU7OlK7iM6SEZ+Zqp+NOOdp/ujY/Rz
         aZiPnfJMqZrlOKmS2xejPxPD42Zu0+mRKx0r+AtpDOxogp2LGPeLnTcYv0BrlJgP3pYt
         mWgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=1qOAyk5NT780gbLfo+HglSQBuMYysholp1kbkQMB9Jc=;
        fh=y/f01HBr+3BRWm65Wd57pF6JxzGUrsRPGtLvdsRGovc=;
        b=J04SyIhzUoH4pmt6Chq/RbXhN+8AAGRjH9c2XaRpwopudbXDCpHxQi1cp/RS+IpDo8
         1XPc9eA7ag2CufO/GagTEzIfMScdc1Ywk5Ec6qAfgdebnxtt7ODoKcgIFyyNrqkieJi+
         Cl0Dc3jmCvTdWiGTM2AS2sL2UvjWXaAnfx1wZMFF6XxJB4PJ3TQ0qtQQtIHpfQLab/To
         FYEMX6Q52hHOyBASari+c0c7r2bD6TufATq4Vp3Z/3naHJtDqHwm7CG24iPggKWJQo19
         5tMD/vWp9aQ19SQPMWi7tCMh8Gib37ZW9jqbnyTGh5TkzxVEzK3jrkL/+vwmqvo+u7/o
         cAcQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="cWPn/YHw";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759214975; x=1759819775; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:to:subject
         :user-agent:mime-version:date:message-id:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1qOAyk5NT780gbLfo+HglSQBuMYysholp1kbkQMB9Jc=;
        b=pYs4h4W8ZxWNxKpMszOB72faNA1XIDPHSzPoH++hgW8p1t3ZgU9EpXXujInt5pEY3o
         erPsfE1DfvXkCSMzLRREIEVDpV3S8g+reG/iAxUs8+tkRDecVkzIALj1MT7Hg0f4PNoR
         M8VgUKOwmMoJrj9BjfjxV5n96tFhBL4UbwXMoNtbuw9X/dBrtHhvIIDsmGjGEIvaISgl
         r79prBMmkRPqS0VVMmKfB0w2VZw1iY7rDFeeM1etFRjEM5dd6LkIEuIi8SjM6b2U51n6
         9amqu8GM86bBzWNKUBdNIWGS7PwNl1xtQkiJPLfBDFcBqWdjP5rXi4awOFUDAlK4FpAV
         HZWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759214975; x=1759819775;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:to:subject
         :user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=1qOAyk5NT780gbLfo+HglSQBuMYysholp1kbkQMB9Jc=;
        b=cFb2p04X4u1Gix3rYYEq58bzFZzluXLBGx8bCc6Z2MDhQISlykaTsvmqAqSdIhifeH
         KPd+ArAvX6H81Ew0jt7chFK2FegtP6J3lH4YkfbPQmc00/BrznE9CyFKfVPV+Dyn4tD1
         eMdDQ+zkP8EOwpGCGyjOlhWtw4LgZeWyIZNivN058vc6W/O0wrpbadCPgdxIYdc7vKPG
         tz/UZIogs72SG7OiMkePy07chp9fe+bpMAOwt+52eKPX4LTe8epLJzTp/M44kqlLO9O+
         g9Wb4C6vk18/Jlg22k2bM6oAnas9onFpw55Rl5TIAfwLFF4+Nh8sfnuQFjfemkeS1GMC
         /LZw==
X-Forwarded-Encrypted: i=2; AJvYcCV7tbW3cLoy4chN7d2j6DchI7WdtmRLW4H7q8l0qlYYlmlJ2XOH0JL6INj3ItrS4FwXcEuXYg==@lfdr.de
X-Gm-Message-State: AOJu0Yzu2mDAt+pTAJ+6IjuTycqzWP/pr/rjRN3u+rQhp/9bKMKymRYm
	pbgtLoRyWRk7RtJ99HOHjUvO5/8gqwQZHm7BrKBM5T12rVllOwnVrvdC
X-Google-Smtp-Source: AGHT+IHUYj06VceygZJoPP8lNPl9XqqvIFvg4ZvS/Ka8esv2iAwFgc4t2YHWdcgogEJhBh9bMyx7bQ==
X-Received: by 2002:ad4:5ba8:0:b0:7f2:f213:d183 with SMTP id 6a1803df08f44-7fc3ca0b6admr268843586d6.40.1759214975578;
        Mon, 29 Sep 2025 23:49:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd7EZShdaCMNv54XCGJ9ASX5iK9/VemVhHhKlZj6wu+wHg=="
Received: by 2002:ad4:42a2:0:b0:70d:9fb7:7561 with SMTP id 6a1803df08f44-7fd83e669cfls63756166d6.2.-pod-prod-05-us;
 Mon, 29 Sep 2025 23:49:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW2c2mnyMgAKu47b+lyC2l78+5U3v9qp596Tfu7/W5iWkTH3AiqyFU6zbEddqVcHLurwgSu92ZnCYg=@googlegroups.com
X-Received: by 2002:a05:6122:3c85:b0:54a:99e2:47db with SMTP id 71dfb90a1353d-54bea3463e2mr7352735e0c.13.1759214974830;
        Mon, 29 Sep 2025 23:49:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759214974; cv=none;
        d=google.com; s=arc-20240605;
        b=RrYB53Z25q/DFNPd/bXtWexfvZ8Ymzl8Dwq9IYFtOkKAyeM5rkxXzUGGUNHE11onIv
         qek9kQ2otHS9G85mgzdwgRawo9dyNpGZLhjRxsuwKTkAR7ggwi5kuEv69hUxVpztZ8zB
         Q9u80lycfhyOrzPYSybXOgk22nJz66WrHuv+ev4IlnRT4JrUoMQ40sBxNig5L4401dtf
         /u3oUZ69p06yt3ZULdH6q2o9dWAjXRGC7sflyppDfnepAycp8zhDcH/kIzJSAIZhKz39
         5XkTsqEwcAaVtk0v5YCZYbOH++euorh56PpTcgDrGM4YH1jaXZeOtxXtGZ5HUnPD8Gcy
         d7zg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=mqRlzhy6X/OCGXbjhJnXJHWuco4CEjpdGpSoiDLw9OM=;
        fh=aFeRgMbAD4Cca+ldZee7Ms4i3KXlzUhKdHpHFrIhpWU=;
        b=Vkn10UBr1H7xBmkYxdqAXyHDGeanuwc2DpYOg60BTkLEN0WkN+TV34cd8yAwmkHGUd
         DeA0NZX3C1k0NlOH97lhOzDz+YlnQU8ESctVFEqhBDuMJv//4cqfIC5RfnofrcpWHA0W
         C8z+V8i+zZbf1uD4vUWgUXopfywkhaBSN85D60dyMAVMsZjZ0IuW1R6MZqVPxSbWvWqx
         jCZAE/D8+2lurf0kraVWot0s73gcSCe+AEVFJDsI0E2f7c6xSFdAyAhLQZu9v+BR5ZFD
         vhE1qBrIDo3kF6yHe0SojDinzTCe/UTPE67X1TkuTSlMdEfVTEVQDLQ0G9h8uOuz5Hws
         SJXQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="cWPn/YHw";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-54bed61b598si571510e0c.0.2025.09.29.23.49.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Sep 2025 23:49:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wr1-f69.google.com (mail-wr1-f69.google.com
 [209.85.221.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-517--UhRVuF8OHW652u8YLy33Q-1; Tue, 30 Sep 2025 02:49:32 -0400
X-MC-Unique: -UhRVuF8OHW652u8YLy33Q-1
X-Mimecast-MFC-AGG-ID: -UhRVuF8OHW652u8YLy33Q_1759214971
Received: by mail-wr1-f69.google.com with SMTP id ffacd0b85a97d-3f44000639fso4098601f8f.0
        for <kasan-dev@googlegroups.com>; Mon, 29 Sep 2025 23:49:31 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUqSmbBDX20GsUUcRyi1ITy4YVhQDJVs+hjT8Uqi8vdWnicbPxKXwGuDX1wnLNXliBj/FCDwJpMrPU=@googlegroups.com
X-Gm-Gg: ASbGncvtgcoDemKhDe4rEiwSPRl4m1ppiYpaz03dsQ+srXyVw64gTVeuD4DeF3x0sJg
	9Bl0oLNXgcVHcdt4Rpdm472VT3k8W0XjX7ROQRTxhZanSrZTD54VnupL9wdt5ZRe4YYMmMWd9e9
	AKYSP4yk+Wzt/JHhHGToGbBHjqVHpLRDICtpn4hOcFxHerCtUobEy1i1I03ZHTtqSEz8jUX6bda
	CzsI0ihC1ZvsMnrvpGyIH8ffapHGEvvnevQujHYUCBWpjsBp6L+KLOEvwMG6Bm4ZzCTcoEG6jfk
	8XJCf5FSTzWxcLCB3ojYds2m31h99DlI3jdFpEq/lOyuKKMulVhH4NokZ66pBOjBmjTVYEEgOgS
	g9SEGY2P4
X-Received: by 2002:a5d:5c84:0:b0:3ea:15cd:ac3b with SMTP id ffacd0b85a97d-40e480ca367mr13436860f8f.30.1759214970641;
        Mon, 29 Sep 2025 23:49:30 -0700 (PDT)
X-Received: by 2002:a5d:5c84:0:b0:3ea:15cd:ac3b with SMTP id ffacd0b85a97d-40e480ca367mr13436821f8f.30.1759214970148;
        Mon, 29 Sep 2025 23:49:30 -0700 (PDT)
Received: from ?IPV6:2a01:599:901:4a65:f2e2:845:f3d2:404d? ([2a01:599:901:4a65:f2e2:845:f3d2:404d])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-46e5b5e4922sm7544255e9.1.2025.09.29.23.49.24
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Sep 2025 23:49:29 -0700 (PDT)
Message-ID: <3ed8a6a5-9983-4b9e-bae1-4c433568de16@redhat.com>
Date: Tue, 30 Sep 2025 08:49:23 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v6 21/23] tools/ksw: add test script
To: Jinchao Wang <wangjinchao600@gmail.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Masami Hiramatsu <mhiramat@kernel.org>, Peter Zijlstra
 <peterz@infradead.org>, Mike Rapoport <rppt@kernel.org>,
 Alexander Potapenko <glider@google.com>, Randy Dunlap
 <rdunlap@infradead.org>, Marco Elver <elver@google.com>,
 Jonathan Corbet <corbet@lwn.net>, Thomas Gleixner <tglx@linutronix.de>,
 Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
 Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
 "H. Peter Anvin" <hpa@zytor.com>, Juri Lelli <juri.lelli@redhat.com>,
 Vincent Guittot <vincent.guittot@linaro.org>,
 Dietmar Eggemann <dietmar.eggemann@arm.com>,
 Steven Rostedt <rostedt@goodmis.org>, Ben Segall <bsegall@google.com>,
 Mel Gorman <mgorman@suse.de>, Valentin Schneider <vschneid@redhat.com>,
 Arnaldo Carvalho de Melo <acme@kernel.org>,
 Namhyung Kim <namhyung@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
 Alexander Shishkin <alexander.shishkin@linux.intel.com>,
 Jiri Olsa <jolsa@kernel.org>, Ian Rogers <irogers@google.com>,
 Adrian Hunter <adrian.hunter@intel.com>,
 "Liang, Kan" <kan.liang@linux.intel.com>,
 Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>, Vlastimil Babka
 <vbabka@suse.cz>, Suren Baghdasaryan <surenb@google.com>,
 Michal Hocko <mhocko@suse.com>, Nathan Chancellor <nathan@kernel.org>,
 Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
 Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>,
 Kees Cook <kees@kernel.org>, Alice Ryhl <aliceryhl@google.com>,
 Sami Tolvanen <samitolvanen@google.com>, Miguel Ojeda <ojeda@kernel.org>,
 Masahiro Yamada <masahiroy@kernel.org>, Rong Xu <xur@google.com>,
 Naveen N Rao <naveen@kernel.org>, David Kaplan <david.kaplan@amd.com>,
 Andrii Nakryiko <andrii@kernel.org>, Jinjie Ruan <ruanjinjie@huawei.com>,
 Nam Cao <namcao@linutronix.de>, workflows@vger.kernel.org,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 linux-perf-users@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com,
 "David S. Miller" <davem@davemloft.net>,
 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 linux-trace-kernel@vger.kernel.org
References: <20250930024402.1043776-1-wangjinchao600@gmail.com>
 <20250930024402.1043776-22-wangjinchao600@gmail.com>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <20250930024402.1043776-22-wangjinchao600@gmail.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: aYSJZ9E3A2AYIHl4cI5yfirNr-Jwjqne9wVYSUVhXGU_1759214971
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="cWPn/YHw";
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: David Hildenbrand <david@redhat.com>
Reply-To: David Hildenbrand <david@redhat.com>
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

On 30.09.25 04:43, Jinchao Wang wrote:
> Provide a shell script to trigger test cases.
> 
> Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
> ---

Do you think there could be a way to convert this into an automated 
selftests, living in tool/testing/selftests/TBD ?

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3ed8a6a5-9983-4b9e-bae1-4c433568de16%40redhat.com.
