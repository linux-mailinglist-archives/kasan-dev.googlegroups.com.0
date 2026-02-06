Return-Path: <kasan-dev+bncBC7M7IOXQAGRB3XXTDGAMGQEBO2LPCA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id wNluBvI7hmnzLAQAu9opvQ
	(envelope-from <kasan-dev+bncBC7M7IOXQAGRB3XXTDGAMGQEBO2LPCA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 06 Feb 2026 20:07:30 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id AF9431026F4
	for <lists+kasan-dev@lfdr.de>; Fri, 06 Feb 2026 20:07:29 +0100 (CET)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-4042a16a369sf5911954fac.2
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Feb 2026 11:07:29 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1770404848; cv=pass;
        d=google.com; s=arc-20240605;
        b=DJrY9RoYpvQ1pahsJ14vtfw3BrTrt3k00uAijuTuCIr64wnoaL3XYncAG+694S2KEY
         RgVEpXXGHgSB2DrPnWrEFrktSSgZNaJs02XAZ/7buw9LFUUNiBU8WFt2EKn1OMBD1bqd
         32PV0A+PonVr+PcoAZoFEKoC4ja4Z0lhURX6OvB6yEWlTVZmbsKZqc1er2KcFU+MU5mm
         vpX6uFU7rLZCTmuDQL5EBtQDml57pchGJU7fD5A8TgngFhZirZFW6fTSeIwRCQ3nKMHP
         Gcb77nh3ouOBmp0iF0hWszp5tr6qTESFhE6FKaDnElIPNFv/eWxYYYXapVhmnTvtuo3+
         oJAQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=No5LSASbOnkO5MDcpHcLJ3mwYg8P3o0o1xESRAlqHXQ=;
        fh=ThW0xYvmhiJcYM2t4bOQojdzoqq3GfeUOw/MGGaTOX0=;
        b=flC0bjaRWnIMjHSAQ0gt9YtB1727FyOTIY7u4Wr+0QU/bK3WjN8GCGCYdiO79NS0KL
         57bxltTKDmhPnyiGZ5YyqMoz2pySeAMAhybjxBKKSUgz5ooJUvL7WjDA0RIWg8HBBOxC
         pR+mIoabXo8Hh4mjgiz9ANlndzGNe1IvU+VB0MUKXXCksNqQDGy8I4ZR65Xq1rcarJ/1
         pVO5we6a9efHETQjFQ5Ckt4hyxQOMJS9R5+aVaMW6f9kkr1Kmed9yFoCHOGCCUnvstyu
         wxuhfdkp9tU5Qe/+b16Ktmkpzrpu3SQeExQK4CfpBxrV6Q83SQyhsjqcObanfhN89s6A
         Xonw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=OYXywpHi;
       arc=pass (i=1);
       spf=pass (google.com: domain of maze@google.com designates 2607:f8b0:4864:20::834 as permitted sender) smtp.mailfrom=maze@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1770404848; x=1771009648; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=No5LSASbOnkO5MDcpHcLJ3mwYg8P3o0o1xESRAlqHXQ=;
        b=GURdyob/vRzsvWdqet6QfIKECv80JO7fCy19bZkNTZCwfB8HjC5b37yqqC7ht5NGH5
         TFwrdz/U2xUEzEVQ4y8Ou27qOX4Z4zm4O9cbDUqc8q7PVs2diREREQ0p8yyiZMd5Ap+v
         WQa2lzNuE2CzFVDx/ayMh5XsHs29+3SenBJhYllLuWHiDvmVSXIt7Iw0T8oMaqvWk1Gh
         sizwfkYkxs1mfXU5IALBqRGXmdwCzBaUNwUlgBN2Gip1qXPwrSKbMPpAlgQ3vq/7A06e
         mLOjqN09pmbZnagVMwzrpMO2IS638wQR5agB/bWL+BRTe2OLAfjBepnV/UazJjnlAHR/
         pT4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1770404848; x=1771009648;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=No5LSASbOnkO5MDcpHcLJ3mwYg8P3o0o1xESRAlqHXQ=;
        b=OxOs397aX0bOSbMriapdHaFdgxizBDCIUCTSIpEXWEx3aPNYWsCvzCIcvdfC5pdjaO
         vD+BvPghJ4suaxa0Fiam3R19/qniMmZ/nZvjBzeEoUnM8cDY6n0pkALQXLDtxpdsjHiW
         r75s+ISzBn/Xf1uNKN/DM0kua8Bk/gUFy1cNU0oXkD1g4yTGTD4yrBc7OoV5beUWEED9
         BgWpLnM4sBSqSycfGqoBU1onzpG54a5Oo5vrSm3oITtMAnyOQRCJ8BChN0HB+vLPsd58
         LySwCP3Un5n+wMFZuC1KVZs/O/FFeVJwCSBytCFwrJ3Z+TKVFfSzg2T4i9p0eCnBn43a
         oHxw==
X-Forwarded-Encrypted: i=3; AJvYcCW4tonSqC14MYAtdc6HUlg8zdr7UQ621PI2NVXtC/WhqD9L/Oa3m1gcYFYK6J4MP0zk10PYZg==@lfdr.de
X-Gm-Message-State: AOJu0YymUfSRw8ALzjNtjWqxr1+39hpG0dxJv5MtTtJVsiLcmOVRdviL
	HdNSe/i93WrvDQYeLbc9LzCMAavbIdGq6AmvlGDwQ3BdmkxTd0s53Uvz
X-Received: by 2002:a05:6870:e807:b0:40a:5c2c:c689 with SMTP id 586e51a60fabf-40a96f8c82amr2077315fac.44.1770404846474;
        Fri, 06 Feb 2026 11:07:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EpstiQf38RyWVeoDwUgAWxj1OZ/RHwxq9zCUxg4z7NhQ=="
Received: by 2002:a05:6870:e9a1:b0:408:894f:e0c1 with SMTP id
 586e51a60fabf-40a74e8be99ls1486724fac.2.-pod-prod-02-us; Fri, 06 Feb 2026
 11:07:25 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCWq23N7wzBNaavsraESiC+gBqGEDRoxtXP3xNiyczoG/mhYrlKjGjAMP52sEDnLIEOi51ETJWT1iC4=@googlegroups.com
X-Received: by 2002:a05:6871:3401:b0:3fe:e04d:fc11 with SMTP id 586e51a60fabf-40a96f364eemr1827520fac.41.1770404845622;
        Fri, 06 Feb 2026 11:07:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1770404845; cv=pass;
        d=google.com; s=arc-20240605;
        b=FJghVGuEFR3YX1jz+rYVf8VGAAKvqaupjHv5bB1N3byqdc26aFclGo0jy//5aH9QLy
         ZF53s2TYiG5IHnfFAHjCVEIrmvhQloILiwLxORX8BtlUNhfVJ3NN2q+lK9vT9u11hP29
         qmY0sMGcc/Z2JabqwQ7fp+7gp3l7+7dx7mZ9kgEjaPqKZTqBty1QqbOTxJUkVWr/bVEZ
         wswlgz58Ot4kJwowO1T+p7Ze9xtU03eApemW8r+cNdKAr02WGg4IfxwgpgBMh9XV0Je1
         arWMIYZMJc0Bt4aIN78xHHmbGD4Mpd95PLjR6r7yHZXD/TirMyXp61qux1NC42y9K1Ra
         otjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ZeVqPtO/zKV/ZDsrHlH8qzY+FDNnYt0+6eW+GIKJENk=;
        fh=sGxlpQHJIWPp2v+JNvfEdfNEyvCm9YekubfO3qO4CSE=;
        b=MK6XKTT71j3G450W15h8r9ulDDsloL76TzNFZp7x69DMK/pgpltdn+14QDq7dYENlv
         m2+fYyFXHgJ6bfhCHyfufXZshZFujIbNvKphpVdkOXp3kjaj+4K3gth8O5uiHvNzGWm8
         k70VFdNF7Zulp5TJYkrsozxV2CQsxF3MfY632t2ugmCKsJlUHcZOIM/zGEVfdJjBiLpO
         X49+xXu8FB3HnHFgy0yb8gC3JxgsovGqZwsspTu8IHgldUhibXurZN4h6WWImHa07VTo
         AXAckMSZbuQAWc9TwoGjUDpF/F/dGhOgDttCyXfaiP5uB013cgYRaOHps83s8iRDrwYx
         4nzw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=OYXywpHi;
       arc=pass (i=1);
       spf=pass (google.com: domain of maze@google.com designates 2607:f8b0:4864:20::834 as permitted sender) smtp.mailfrom=maze@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x834.google.com (mail-qt1-x834.google.com. [2607:f8b0:4864:20::834])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-40a997e9625si100833fac.7.2026.02.06.11.07.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Feb 2026 11:07:25 -0800 (PST)
Received-SPF: pass (google.com: domain of maze@google.com designates 2607:f8b0:4864:20::834 as permitted sender) client-ip=2607:f8b0:4864:20::834;
Received: by mail-qt1-x834.google.com with SMTP id d75a77b69052e-50299648ae9so48341cf.1
        for <kasan-dev@googlegroups.com>; Fri, 06 Feb 2026 11:07:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1770404845; cv=none;
        d=google.com; s=arc-20240605;
        b=RSi/L2NMNAJmzzQpEw1R1hmQExd3R9nOk+RAFwFYcAhl2njtgKGNXjOgAnXHI5JRet
         IhR91VhD9g6arG3tPOmo/59YwdGboxv3Us12pQPerVAB+LpHPDI1pWLjaZV4VRa+wLJT
         1MAc5BZg8ZNgmLemERvbgBN8d3P78vXmqo1SGJvcCDJOBGQ7SJwI5A2P13ikNENs7Vbx
         MO44oRAP+42em1vBSW7OyeokKlNWbbbBoLATAW2x/T46VgNexFJUBVvNi7oaqnUOKjiu
         bBehI/kWx1GxaTLXgoTdPaIQYjX8BNpoGxFKwnUPU/VEJX+xwW0wfaahdpOr10Tx2xQ4
         K5bA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ZeVqPtO/zKV/ZDsrHlH8qzY+FDNnYt0+6eW+GIKJENk=;
        fh=sGxlpQHJIWPp2v+JNvfEdfNEyvCm9YekubfO3qO4CSE=;
        b=X8WLJS7nDO+FljefkapOV4EEnFapaZo2wj0YJk5DRh8k76zUwzU9OwiqgO635UW2Eo
         X8j3nmJh1WJkLX+Tj9SAZcheEOYayTYs7/8ij1OC/vEt0OuB9wl4RiWzKKWZHuZvTvTb
         L6Nor5IFMfyU/1T4bSpZP9RhiR+cVMEVnqhn74qLh06Y+KZdmE8a28lgJ4qDIqo5+4qK
         s64TPPfkeAzHCthyzzcliLgIXAu/7Ih38G0hlzlwd9tVh/t8BrZm6X6niVuqkRJvdumO
         jaVOwoyO8bQQxffciGjtELSVjllkg6RgwoVBWQagyKTtdwr5ggjTQMqRrRocOD10hgXp
         5eiQ==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCWAbRpnpscf2jlUwVMZfpTyOaCM/W58I6mNCO2vl2RfxXUEFZMkYh0baQVKVNr4wMktKxKAi7CJgTQ=@googlegroups.com
X-Gm-Gg: AZuq6aIGHAgYrNkHHX60NoHD+lnzoGp/dp19eRbg527vDVytAQ5d/6BiyKTq3WJ92rJ
	C32DyWB9pRazUoHcSckup7Bt0ozcQbPaKjOvVcmljzhnC9y8e8OHy+T6NOpltQ54GtgPf/EJm+N
	JHdTGR04ewcxqYlOt/HYn8AOLAbrEYxSOlN/g7KWhEqDZ8CDuE7V97blueso1Genybztc6lUqx3
	/3H8WR7vWyGAd9OKVI4nEbkg8A/FcVHlh2spQV3c5RDxADJvLLdIVmByg/qhxOKzyWC8AglLNbJ
	6b2q5zPyLcQxhgOAtTk75qz1j9DMoSZfCeWINk9scA==
X-Received: by 2002:ac8:51c2:0:b0:4ff:cb75:2a22 with SMTP id
 d75a77b69052e-50649ca8c6bmr598641cf.3.1770404844843; Fri, 06 Feb 2026
 11:07:24 -0800 (PST)
MIME-Version: 1.0
References: <CANP3RGeuRW53vukDy7WDO3FiVgu34-xVJYkfpm08oLO3odYFrA@mail.gmail.com>
 <202601071226.8DF7C63@keescook> <btracv3snpi6l4b5upqvag6qz3j4d2k7l7qgzj665ft5m7bn22@m3y73eir2tnt>
 <CANP3RGfLXptZp6widUEyvVzicAB=dwcSx3k7MLtQozhO0NuxZw@mail.gmail.com>
 <CANP3RGeaEQipgRvk2FedpN54Rrq=fKdLs3PN4_+DThpeqQmTXA@mail.gmail.com>
 <CANP3RGcNFgLSgKYPjmro2s1Es04Pnhf+4wHpnSwRX4M8bLDW9g@mail.gmail.com>
 <aWFKEDwwihxGIbQA@wieczorr-mobl1.localdomain> <CANP3RGeWLMQEMnC03pUr8=1+e27vma1ggiWGWcpX+PcZ=SsxUg@mail.gmail.com>
In-Reply-To: <CANP3RGeWLMQEMnC03pUr8=1+e27vma1ggiWGWcpX+PcZ=SsxUg@mail.gmail.com>
From: =?UTF-8?Q?=27Maciej_=C5=BBenczykowski=27_via_kasan=2Ddev?= <kasan-dev@googlegroups.com>
Date: Fri, 6 Feb 2026 11:07:12 -0800
X-Gm-Features: AZwV_QhSTkSJ_KynPb24QBIc0N9LtzMU3n-qIIiw27uPu35C6AHY-mN4QWU-75A
Message-ID: <CANP3RGeHnhufYyc0P2OiKJbXdZjPW41TP=JS6nYk9xGRU8UuKQ@mail.gmail.com>
Subject: Re: KASAN vs realloc
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>, Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Kees Cook <kees@kernel.org>, joonki.min@samsung-slsi.corp-partner.google.com, 
	Andrew Morton <akpm@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Marco Elver <elver@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, 
	Danilo Krummrich <dakr@kernel.org>, jiayuan.chen@linux.dev, 
	syzbot+997752115a851cb0cf36@syzkaller.appspotmail.com, 
	Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, 
	Kernel hackers <linux-kernel@vger.kernel.org>, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: maze@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=OYXywpHi;       arc=pass
 (i=1);       spf=pass (google.com: domain of maze@google.com designates
 2607:f8b0:4864:20::834 as permitted sender) smtp.mailfrom=maze@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: =?UTF-8?Q?Maciej_=C5=BBenczykowski?= <maze@google.com>
Reply-To: =?UTF-8?Q?Maciej_=C5=BBenczykowski?= <maze@google.com>
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2001:4860:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBC7M7IOXQAGRB3XXTDGAMGQEBO2LPCA];
	MIME_TRACE(0.00)[0:+];
	RCVD_TLS_LAST(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_THREE(0.00)[4];
	FREEMAIL_TO(0.00)[pm.me,gmail.com];
	RCPT_COUNT_TWELVE(0.00)[19];
	FROM_HAS_DN(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev,997752115a851cb0cf36];
	NEURAL_HAM(-0.00)[-0.999];
	FROM_EQ_ENVFROM(0.00)[];
	FREEMAIL_CC(0.00)[kernel.org,samsung-slsi.corp-partner.google.com,google.com,gmail.com,arm.com,linux-foundation.org,linux.dev,syzkaller.appspotmail.com,intel.com,googlegroups.com,vger.kernel.org,kvack.org];
	ASN(0.00)[asn:15169, ipnet:2001:4860:4864::/48, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	HAS_REPLYTO(0.00)[maze@google.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail.gmail.com:mid,mail-oa1-x40.google.com:helo,mail-oa1-x40.google.com:rdns]
X-Rspamd-Queue-Id: AF9431026F4
X-Rspamd-Action: no action

While looking at:
  https://android-review.git.corp.google.com/c/kernel/common/+/3939998
  UPSTREAM: mm/kasan: fix KASAN poisoning in vrealloc()

I noticed a lack of symmetry - I'm not sure if it's a problem or not...
but I'd have expected kasan_poison_last_granule() to be called
regardless of whether the size shrunk or increased.

It is of course possible this is handled automatically by
__kasan_unpoison_vmalloc() - I haven't traced that deep,
in general these functions seem to have a terrible api surface full of
razors... with hidden assumptions about what is and is not granule
aligned.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANP3RGeHnhufYyc0P2OiKJbXdZjPW41TP%3DJS6nYk9xGRU8UuKQ%40mail.gmail.com.
