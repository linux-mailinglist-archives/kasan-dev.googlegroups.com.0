Return-Path: <kasan-dev+bncBCSL7B6LWYHBBG7IU7GQMGQEOTHCOPY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id eMrwOh70qWljIgEAu9opvQ
	(envelope-from <kasan-dev+bncBCSL7B6LWYHBBG7IU7GQMGQEOTHCOPY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 22:22:38 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 94AFB21878A
	for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 22:22:38 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id 41be03b00d2f7-c73935acff2sf429916a12.2
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 13:22:38 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1772745756; cv=pass;
        d=google.com; s=arc-20240605;
        b=R3+PqqiToXs+jwpN9mZoCLGrC8/6F/FiNcdqnD/yt4qg7Avi2QvbpLkiUrxR2P628m
         G5Yf3QAu6nXne6VHb5/YXUlGJL62f2fNQ4hPKjGQSQyZmlvcwZOXD9SfTDSyI7LhPtM3
         azfv5j6AJBFJsLSLK6Dx0k7W//I2dp94ZiPzNH6zcQPyTN64npuqhsZDH1sN6BiewB/D
         8MQ5Wc6VQ61v3F3R2FzLDI5YEhhvQwsD2t4Y095RQueWKz0ilc1S+FE41SZcIZxA3ALY
         hxy1TBcDVElS/+Y4G7CQMLYhcPjxOvsqUlMVeS57IFBTuc5h7MujjF4DEJUPpghgSKbB
         P8Jw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date
         :mime-version:references:in-reply-to:from:sender:dkim-signature
         :dkim-signature;
        bh=D4JJFo0XXZvIHP9xfR1wrxorGhtUI3IMwwOKl7gXT9Q=;
        fh=acaDfE+qWL+upYpPUTULRe5oTsykfGyzifbVXHWNk8Q=;
        b=G6JdAKc5RlXprXdYJ/3xDL/l0DWbz60fq5BMEj/mMP4h6LISKPtxF/To5i65lsApTK
         U0uXO0JqxUf9y659EGgNGjDQYIDOCvkdLHV31YVeP/luwKxU4FfiIVBOHH+qM2nLx4P2
         wDnZk1RxDKpp+qOz/AEQLWrfBW6zcIrB/UDfLgs5u4xzvd/2mvKSbGdx9XcrPs/mF2Nc
         32pIPuQC6YtG0MXr7i9XVO0Km8L8Fcc3YOFUGaTO++nwuvqbnQEfUjAkh1xo7/DmEbWc
         AXPyBxgx+98cloICmuiMPm2ZlB+dDfMb0RylZX+Knwj2aadJm6DVdgLV5ExcbKFTo1mu
         Z6nQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=MAQWTrUr;
       arc=pass (i=1);
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2607:f8b0:4864:20::1131 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772745756; x=1773350556; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:mime-version
         :references:in-reply-to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=D4JJFo0XXZvIHP9xfR1wrxorGhtUI3IMwwOKl7gXT9Q=;
        b=Av6B4zncSCV+n08rQtfUuSxYZe5+wjfYolcl5+y9SnPURcuV4+qB2WPJICEOg0xSvI
         Ow3ZY+9pogJqGkrcCwiotbuQk53r1mxIgoLraELmKQBtgkftPtdwVras2d0uMrgJy225
         tMiIUWURXjKHKjWthf5JGI7wEd3gzJJL9xnR+VVV4aagjwAeEnArw+h1r6VBadhf6/KR
         /WeJi0rw4wW7vEJfz80ah7OvLT3BPG7ECjiSJqPNEnAEe2l3+ULP2PpjjZpVJCEghg5X
         /i9woNiRO67MnbGHXhbC8jHq5wSnGUx0LiL3JKYwTfr5c+6Q1vBUDEiyImXbf5EIuGJf
         sBsA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1772745756; x=1773350556; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:mime-version
         :references:in-reply-to:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=D4JJFo0XXZvIHP9xfR1wrxorGhtUI3IMwwOKl7gXT9Q=;
        b=VnSsUNWk+bR6vLTt5a5a5s3eWoxUB3ZAWYujn7PGNm0h1Z16kXqqxWoY1HWYAdrvvs
         bOqTY7t7BIZ+jjRUwxx2CqWXq/FO+rta+5ccvm18TWizEPqyk45IeHEQ9Eoy4q3Mvv0q
         DZBJfA6XuXRpWKv0JM+J0gXZeZYVbHa82Onad66mlKQ2yYtTu4aBQxWseu8nx8zwZHXD
         7Soe+cMTMWyAXPJA0s0l1RqTZiSRXaC2PTBe6DSum8OE2KXPPAni3mzhXFOxFoEqokVw
         ow1UAnWPm7SbD/0UxkB6kkhnvqmyRkBbDr9R0MPaZ+n03d13/n3kMkdpmZz0n+ctvXvs
         hkJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772745756; x=1773350556;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:mime-version:references:in-reply-to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=D4JJFo0XXZvIHP9xfR1wrxorGhtUI3IMwwOKl7gXT9Q=;
        b=thIOpClp3s40Ii6ODJwGqKgFlrUQFIRzXiXHpziHKGDT79fZHuc2MJArmHAgwJnD0W
         1cqfUiX666FonAgX1O5FkVRInXZ/QSDo85L5ygfbRuvXTG/7TlQoxLAkXErgBp4oAdvw
         ssG6RhSfrk9I3p3ntZgRQvLf0MfXxBcgCWTixDcNgX2sVSIlj84mTsMmmuhdoPtVmRp7
         orG8jaSiE8g+lzyGy6JWMvnBY2iR88QC52IDo6s0GvPspKPsZo7VsW/QKhPzFdvVl9aD
         CSIM9R807zXhen4/oJRfd+YcUcJ8zjTdhbVnf9scOTwSWLaDL/uPM6jq+RxcTVRDpNGC
         9Y5g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCXwybvJ36nsu1JPGC2jNiNUFVKAO13u8uFS2YJrq821VWu+yaaoz4clpUFV46OvSOq10tnj0w==@lfdr.de
X-Gm-Message-State: AOJu0YyTYuNUADQB5eGu5cGf3cYrupBWimIaFX/7cOjndVNaqph21PLX
	dDNNztxeUohT++x4tgR+KSviISOc30+0WkhQ4TcmYCmFFq+z3EuQciYe
X-Received: by 2002:a05:6a21:4a98:b0:35f:27d:2ded with SMTP id adf61e73a8af0-398549981e6mr934662637.25.1772745756316;
        Thu, 05 Mar 2026 13:22:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Hpr4JHOOepe1U/bozkgB/ewIi/FKke+rKcTXAlUGFWog=="
Received: by 2002:aa7:9f4e:0:b0:7f6:3f21:7d71 with SMTP id d2e1a72fcca58-82980cea714ls1063509b3a.1.-pod-prod-07-us;
 Thu, 05 Mar 2026 13:22:35 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCVi1ibgMP5G9BAuHl3o9GBq5KyBaDowm/wKFjPtEPBdSusaNtNbvMR9sIZrN6k4g5egiLRcV8Febik=@googlegroups.com
X-Received: by 2002:a05:6a00:759b:b0:821:8ebc:2899 with SMTP id d2e1a72fcca58-8299aa197a8mr817636b3a.7.1772745754777;
        Thu, 05 Mar 2026 13:22:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772745754; cv=pass;
        d=google.com; s=arc-20240605;
        b=NML4frI0VqDugcyqvHelYg2+xoFx0UNk/80S1DXYWKsxlxcM81DqLf40lflzoNSKCq
         K4AnYJbgtdFta3dcqif8aZsGjKug08Fl/9tmjT8+VMfgk8s3CRa67m7kOQLGDtR2AtNA
         j+noXlNBNppVzW5HCtngHFxjqk4VYzGUllshxdGDFAX8VcOeHQaWWKzzsXU74DfzNrdA
         Ox5SE6Y9BBKy1gNeIcgZoFzIqvLJVz7VuZ+CVx+qwPF8LxgjHsas/0a3FqutXwE7tpzP
         dnG8iIqgsjobTn9jgxc3Xetum67grhnxaRWfBtwv6nDIlrHleyeWVsFovfn8MrX1+h8c
         VUxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:mime-version:references:in-reply-to
         :from:dkim-signature;
        bh=xRV4KrgPufJHYoouG5oBzfgHa9sX1mic2JP1prCF/Sk=;
        fh=h40zj/pQOhalQB5sLQSu2uxoOvd5ROEvOejrnlqNtk8=;
        b=FKfzBu4HJtZ7z09Hl+2ZKBdewXr8cQ9gvhF17QqdO7Qw/TmYYdJ5OK5MIijeXkpoIX
         M+ZIc/Mu9qm0jzpzorUc2hb7yQ08kJay9sgzfYPWcEwV9ESsk+fEKtZ9AjxhFZwFL74q
         HmrsCFQeE0Em1v5LXiA/FnCKZ5gpA7RwZ9dV90jeLWqUXPMxFJlv3IBtxyL9d9kD5eQ+
         lGG9YJh6vtI197+UEyg28h/Q1hO03vHwE8ragzXAPzxDGDecO3R8SWySsWuwVXE3UD95
         61OpzsDzfXMJCtUH3QVNQ23Oa4bWtjTvsi68o0GNwfYX3AAqQGyf7ASNWXgvuc1cyasf
         qOdA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=MAQWTrUr;
       arc=pass (i=1);
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2607:f8b0:4864:20::1131 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yw1-x1131.google.com (mail-yw1-x1131.google.com. [2607:f8b0:4864:20::1131])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-82990b0ab0esi61696b3a.2.2026.03.05.13.22.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Mar 2026 13:22:34 -0800 (PST)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2607:f8b0:4864:20::1131 as permitted sender) client-ip=2607:f8b0:4864:20::1131;
Received: by mail-yw1-x1131.google.com with SMTP id 00721157ae682-79852e01cd1so3881207b3.0
        for <kasan-dev@googlegroups.com>; Thu, 05 Mar 2026 13:22:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772745754; cv=none;
        d=google.com; s=arc-20240605;
        b=O4E/f6n2/npD/8Wz8gCTiIh7JFCCPbWfiHjZFAmfWLfjxUM48XnO9Ic6nUKzqXmCVv
         hCE/bpY3KM2bqisyzgh+oSguOAFGPBIJZW2zNCRMuZd1rhZLui9WiYklJzuCQrWvn58I
         6Ms4n33avUJ4sJcYwML0hiIIawkoc/gQlaUo1vSx8ORvDbDAeKnkaV3IlqK62Gw8NF5w
         VUA9I9qiaBH9qNJUu6scXCjiA1nPxJDOJX5UYLZA03d8r2PnSBVfismqStORI0dDKeHX
         UdzlGSGFCJz3w/eAAvJLyR5udAYzhxcaMY0A1UPI0Kq5jrduGIBEL+a9mWKTVI3+UAhE
         D0GQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:mime-version:references:in-reply-to
         :from:dkim-signature;
        bh=xRV4KrgPufJHYoouG5oBzfgHa9sX1mic2JP1prCF/Sk=;
        fh=h40zj/pQOhalQB5sLQSu2uxoOvd5ROEvOejrnlqNtk8=;
        b=GGrEZtOoi2+s4T/6kWRqpnDD5CC2Xovyk1murMT/xTJlHt1QENgz7lQOXApdtv+cnA
         tekFDVCf1aMUotvsTkxwYL2E852K6Ko4Oqd4sRUHfock7awnq+vcjcxX/TXXm6hbZwcy
         9gxsOegGQ8cqckVoy4GyVapzpLcglIF0K0Era/FBUTCru01ymA+y4cj80u8PQ+XM+op+
         F8qea2KnrPWR9mpiPFyZ2HE9bD3fgk2um6L1i7+j2bzXgOd3GauZuTVlzx7BqPa4V2lu
         OzQ33LkP9udCs+2cbK957aQ7XzP9CNBw0YvJKHCZ/sHRMMNLI8Y2rExkb4MO5orGAFwf
         quxg==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCXzUrbJVafb6FnujWNMX2qYMWFUamy/IFBKxFUMKoeK8JhzjDT1G+C0CnPe2OXYAoSazEFelU2ac6c=@googlegroups.com
X-Gm-Gg: ATEYQzzWaiTSkrW4C9x36VoCk6niPsGqPQdSYlf8MSYCAyU3vEd0UeZhvsqRgslRFju
	AwwabrXYi6sUCFCTz6k8E/U/nXvxA7H7ypESYx7RopNoGhZPXpRh5HwbeTAfrhEgoWQZNUgearD
	hWR32dyLgE//4BEHHV5oMTNchIgEFADdgO932MovW5sGtJlIGr2HBcZIYRK35IcdxswPKR237ia
	XTPFQ80XBCAeHjdKYhmTcmJdAGwK9TDV5bM8MdejFjnHQSNLUZDtCKrumh2qA4GZRlMPP9i5b3L
	vC2ElZ5L
X-Received: by 2002:a05:690c:385:b0:794:2fca:81a with SMTP id
 00721157ae682-798c6cdffacmr55975367b3.8.1772745753906; Thu, 05 Mar 2026
 13:22:33 -0800 (PST)
Received: from 95991385052 named unknown by gmailapi.google.com with HTTPREST;
 Fri, 6 Mar 2026 06:22:32 +0900
Received: from 95991385052 named unknown by gmailapi.google.com with HTTPREST;
 Fri, 6 Mar 2026 06:22:32 +0900
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <aanievpHCv0Sz3Bf@wieczorr-mobl1.localdomain>
References: <cover.1770232424.git.m.wieczorretman@pm.me> <bd935d83b2fe3ddfedff052323a2b84e85061042.1770232424.git.m.wieczorretman@pm.me>
 <CAPAsAGxpHBqzppoKCrqvH0mfhEn6p0aEHR30ZifB3uv81v68EA@mail.gmail.com> <aanievpHCv0Sz3Bf@wieczorr-mobl1.localdomain>
MIME-Version: 1.0
Date: Fri, 6 Mar 2026 06:22:32 +0900
X-Gm-Features: AaiRm539DykMmBy-Zg-BtYOlfUPQKOJ6bwMQcvFff9WH9ZMuhoRcwF9c8D83p3A
Message-ID: <CAPAsAGyiukChPLYO_tQci-7Bvmnnxh+w=bO6eUYLrO3RVuUThw@mail.gmail.com>
Subject: Re: [PATCH v10 01/13] kasan: sw_tags: Use arithmetic shift for shadow computation
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Jonathan Corbet <corbet@lwn.net>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Jan Kiszka <jan.kiszka@siemens.com>, Kieran Bingham <kbingham@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, 
	Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, 
	Samuel Holland <samuel.holland@sifive.com>, 
	Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, linux-arm-kernel@lists.infradead.org, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, workflows@vger.kernel.org, linux-mm@kvack.org, 
	llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=MAQWTrUr;       arc=pass
 (i=1);       spf=pass (google.com: domain of ryabinin.a.a@gmail.com
 designates 2607:f8b0:4864:20::1131 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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
X-Rspamd-Queue-Id: 94AFB21878A
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[gmail.com,none];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601,gmail.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBCSL7B6LWYHBBG7IU7GQMGQEOTHCOPY];
	RCVD_TLS_LAST(0.00)[];
	FORGED_SENDER_MAILLIST(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_CC(0.00)[arm.com,kernel.org,lwn.net,google.com,gmail.com,linux-foundation.org,siemens.com,sifive.com,intel.com,lists.infradead.org,vger.kernel.org,googlegroups.com,kvack.org,lists.linux.dev];
	FREEMAIL_FROM(0.00)[gmail.com];
	RCPT_COUNT_TWELVE(0.00)[24];
	FROM_HAS_DN(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	TO_DN_SOME(0.00)[];
	NEURAL_HAM(-0.00)[-1.000];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_NEQ_ENVFROM(0.00)[ryabininaa@gmail.com,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+,gmail.com:+];
	MID_RHS_MATCH_FROMTLD(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev,lkml];
	MISSING_XM_UA(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[pm.me:email,googlegroups.com:dkim,googlegroups.com:email,mail-pg1-x539.google.com:rdns,mail-pg1-x539.google.com:helo,mail.gmail.com:mid]
X-Rspamd-Action: no action

Maciej Wieczor-Retman <m.wieczorretman@pm.me> writes:

> Thanks, that looks really neat! I should've thought of that instead of making
> separate arch versions :)
>
> Do you want me to attach the code you posted here to this patchset or do you
> intend to post it yourself?

I think you can just squash my diff into the subject patch.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAPAsAGyiukChPLYO_tQci-7Bvmnnxh%2Bw%3DbO6eUYLrO3RVuUThw%40mail.gmail.com.
