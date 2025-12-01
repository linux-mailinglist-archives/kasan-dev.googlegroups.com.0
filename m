Return-Path: <kasan-dev+bncBD2NJ5WGSUOBBTPIWXEQMGQEN6B4S5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 283A5C96C3D
	for <lists+kasan-dev@lfdr.de>; Mon, 01 Dec 2025 11:56:16 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-640ed3ad89bsf6050674a12.3
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Dec 2025 02:56:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764586575; cv=pass;
        d=google.com; s=arc-20240605;
        b=JGUok6jHauBMgBLqmLIIpZrPnsJx21aYHRy7bfehR+Qx3XF5LAZQWtv5GF8AVyt8Cp
         WPwsPJTyz6pgd/Ph7BadS/exsgTTGSXquVlNxqf7HNse+oUSESddrP2PId8npEqnq1iv
         vAeAreD9H9TlB4pJwPMlB5/9kQ7s3HU4tMsRatTjPlZl8U8Z4rJ2dO3B3+zYju6IMWOd
         hV9njqfDOtOCfQ+tkV0ITbzuR0Xljdaw6W2Z8fK2HChIiTKpKmABmEhta4uQWAkCE1Uv
         dJXyHkp8HeTk0MC2fe6m3yW+OwHjWLt9Uxx3K/xtfVM273wJRn2jBqv6+6Y+LIhT0P+m
         VkpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=hwZ7eKbDUC7UQC99Bl8QCp2QKlDbh8uhQTXHLo05lH8=;
        fh=g0jbvibRjht8XB4aMdsnTKDzNJoyq96lKhvgDhj29sc=;
        b=H9K/DeN0q/h3mZLvpphuvV3JedEhAOouENPrPrYtUnLid1J4T2wIbXGCtt0q3C/JRF
         Kvtjq+XyWLlMoyzzmN8XKkCHTYYsRnos4XV429cQ17DarNpH1m0r/dRE/kkVxm2tXBbH
         4ZoU4Lq/BZh3xKZ06AozK+32H2k0wkKSxa8K2oAb1pab6OqhkqWrSBtx/PjCSK8zd4cU
         i2qGxHXUII8eJym2wactXd0sx9DlFCPRBfcooOae0qQ9wrXc4iOGgzVQBKrYQV49EyaN
         f2w6zdDCaaCbFemB5BQyNlZnVbpLs/0/nxxuiG2jQnqKrk9WVHRWo9/feHZOe7FVbVII
         igvA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=saWbKHsK;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764586575; x=1765191375; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=hwZ7eKbDUC7UQC99Bl8QCp2QKlDbh8uhQTXHLo05lH8=;
        b=Ysvk5amhizG7+d0aZGPRP9Kx8Z5dnteoWl2Up+UIZEVWG5Y3Od0RTtU6t7e5IxFben
         PGC7EwGJZ2gX9yCUQiI7J0hbMUi/8CIcAh30UOF5NgPAh9MRcEDsHl7VM7hUFBKHif3l
         QqxgUEFNzaOK0LOKbR3h5qG1gGrxTXwt0pw3TBaho7xwDFHa/d3eGXDSpmypy/gR2SpK
         cLt6AY89d/LwzOHlE9dIZJapQpKSFmWu64Thaj+s0FsFl3Z5D42vQvbv64q7QuswMsdG
         fYm8QUhoSnQ9weVtHRzrYT3ePQro8q+Ccpulvyv8ZM9drSSsvRYxBrXd3eK/1sUFcBw0
         0aqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764586575; x=1765191375;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:date:cc:to:from:subject
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=hwZ7eKbDUC7UQC99Bl8QCp2QKlDbh8uhQTXHLo05lH8=;
        b=XDLtURZYtkPL+QlpmyvxciTfWbzXvDtDGCBavzrRXvd02paO6AymcKB6bHvTTPUCsq
         kznsvSRqhgYxIFPJppqCyaf6zNj+O+o6fYa+0iai2BaiffFLXivk20N2QY+Jg3waALc9
         gqwMW+hvBgRGyfF36YQH5X2hv78vXIxyI6HyAtj2kBhmKFNm2l6m9UJhRRU9lq7aCN5X
         YxlwMDnmNj6MlxwRDN/TQ+e0rZYXdOzW9r4WY+nWmYjEQQp5q7lh55uMkWqju5qPC4VD
         s57V2jEhXToVdyLBWOCelnSz28cUacyXFB5ZuSUY1ZNijmivmda+LhYx4wINok69t/cg
         UzOg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX+9rSPbN9/Vqyx704rYjokWpRnSVSTav31rWVlybWela9A3to8+VqrJ+7cKruYi3Yb1kb/iQ==@lfdr.de
X-Gm-Message-State: AOJu0YyZnahIi+O5H0i6Hpq1HsUYc7yfM/Up9cg+MhRXjsTktaRifncS
	I8V/mKF41ld32Cye5XM5SpcEzrXIDRvF4daVVAipkCnw23w8yny6I0V3
X-Google-Smtp-Source: AGHT+IH5/INqp3LD0ops/HPlQdkL7BkN9KjV14jWba+uKFNc0OGQQ5wh2nERoStnpZttldE8rMqmPA==
X-Received: by 2002:a05:6402:4405:b0:643:129f:9d8e with SMTP id 4fb4d7f45d1cf-64555b9aafamr33525984a12.8.1764586575089;
        Mon, 01 Dec 2025 02:56:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Zh30fxcXiIy6qw9qWdrEMM/kbtUPbT64FZ81D8a4nhnA=="
Received: by 2002:aa7:cf11:0:b0:641:6555:a42d with SMTP id 4fb4d7f45d1cf-64749b0279dls4185369a12.1.-pod-prod-06-eu;
 Mon, 01 Dec 2025 02:56:11 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVMdmMgImHr9rdNYuZsQ7vlJCTAKp9uej3Rvf4WXOZe4XwlGnMWi09vbwqRbymaJTaofSXC43q6jyA=@googlegroups.com
X-Received: by 2002:a17:907:7292:b0:b70:b077:b94b with SMTP id a640c23a62f3a-b7671a7c4a8mr4285333666b.43.1764586571746;
        Mon, 01 Dec 2025 02:56:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764586571; cv=none;
        d=google.com; s=arc-20240605;
        b=cAlVI0pgrYz+qc5iXlDOtw4jScQLRvoG/W52H4v3GqlriKOg8X4Y5CnR7V0nwuiSQo
         aFFEIBqvDCPBftXSG0GTInJNgrOWgKJzEIZJlfOnf6qpeCpGHjOunmG49tc1GH+Qh+Kp
         sK0jeX0ri34Gv2LXBldA2p+yuq4HWdFV+fRJrCtwF7iMHMH7FSDKjYfUFixXHw+yVNdg
         xZ3FLiKY2SDrFfMJdJJrfI7iiJmrfrbAFguEvCzHwJiy1+iartfrZreJfzgFp5jeZDFu
         He+AdW7nc5DLz+NYf7WgTMKksMaozdkSZyHByzC4dTwzDDd4SYMFe4aQgbNE3OhLsllX
         qcdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=tiRNEO/XNBxkNs9MPPdlx3M52d9PmW2KoL7nHem/Ym0=;
        fh=EXepbpZFlKLZiHpaMNrfLSbccl9VxN4Mqq50pyT6lXk=;
        b=DwVg6V8YR2MYmBYZArXhTUaNo1pkk17eJ4MEKEtAbzZux7ZxkAaE+ZNEyuh23r3sd5
         Ss86lvyXe68zZHsEvzZN2Jloi7OYzRolK0eB85j8YpH33mrU6MO+ejm/JNZvgVIGRNmJ
         SWR1ZOTlO11rJC3TU04swE5MT5CGSEDcCcNGdSRbFCmThS6FLqZD/QtLINDN9BLubLsU
         n3thB/G4r1XbWDDxxsnKmKWPQFPIqt11D4PpLGJGoJUvntP4ASOpe77YEKvtyPZNKJEG
         10Qr0kh6jJoJ3L5SAhmlmaoW6FgWANjHqF4vgeUhHWyyp/X5jdFCmUQcPCTD6tgaXakw
         EiuQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=saWbKHsK;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:242:246e::2])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6475102bd85si324735a12.7.2025.12.01.02.56.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Dec 2025 02:56:11 -0800 (PST)
Received-SPF: pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) client-ip=2a01:4f8:242:246e::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.98.2)
	(envelope-from <johannes@sipsolutions.net>)
	id 1vQ1Zf-0000000D35i-0PYH;
	Mon, 01 Dec 2025 11:56:07 +0100
Message-ID: <86d982368a85ab9dde17e52b45e77f5f76efea08.camel@sipsolutions.net>
Subject: Re: [PATCH v4 11/12] arch/um: don't initialize kasan if it's
 disabled
From: Johannes Berg <johannes@sipsolutions.net>
To: Baoquan He <bhe@redhat.com>, linux-mm@kvack.org
Cc: ryabinin.a.a@gmail.com, andreyknvl@gmail.com, glider@google.com, 
	dvyukov@google.com, vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	kexec@lists.infradead.org, elver@google.com, sj@kernel.org, 
	lorenzo.stoakes@oracle.com, snovitoll@gmail.com,
 christophe.leroy@csgroup.eu, 	linux-um@lists.infradead.org
Date: Mon, 01 Dec 2025 11:56:05 +0100
In-Reply-To: <20251128033320.1349620-12-bhe@redhat.com>
References: <20251128033320.1349620-1-bhe@redhat.com>
	 <20251128033320.1349620-12-bhe@redhat.com>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.56.2 (3.56.2-2.fc42)
MIME-Version: 1.0
X-malware-bazaar: not-scanned
X-Original-Sender: johannes@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sipsolutions.net header.s=mail header.b=saWbKHsK;       spf=pass
 (google.com: domain of johannes@sipsolutions.net designates
 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
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

On Fri, 2025-11-28 at 11:33 +0800, Baoquan He wrote:
> And also do the kasan_arg_disabled chekcing before kasan_flag_enabled
                                     ^^^^^^^^

typo

> enabling to make sure kernel parameter kasan=on|off has been parsed.

But I'm not sure how to understand that sentence.

And I have no idea what to do with this patch, with it being random CC
of the middle of the series.

johannes

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/86d982368a85ab9dde17e52b45e77f5f76efea08.camel%40sipsolutions.net.
