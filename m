Return-Path: <kasan-dev+bncBCUY5FXDWACRBZHAZ3FQMGQEWWPMSEY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id uFQqMmawc2nOxwAAu9opvQ
	(envelope-from <kasan-dev+bncBCUY5FXDWACRBZHAZ3FQMGQEWWPMSEY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 18:31:18 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id DDCE379097
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 18:31:17 +0100 (CET)
Received: by mail-ed1-x540.google.com with SMTP id 4fb4d7f45d1cf-658102e94c6sf3133743a12.2
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 09:31:17 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769189477; cv=pass;
        d=google.com; s=arc-20240605;
        b=RAMWxyO/NeF1GxJLN8CaLnHAgSHyMgtodFBl/PJ6RpBpE2Le5TYJm9ts/tTNgQ9aMl
         QCq51inE7RTUTYBrwB7my9pDPZWMOysDiSNuhaYZZetUCvC1Km/QF3gWmqTeM8lUpP+X
         MsxHoHuF6ksGZxuHGgbjfX3xHcRoYnkQYfWBjbsaDs3/jxJBYINoXDUB0UlxFnInSivP
         8b87JRlHw/LbwkJyAXYx6e7reAaBJr5l6dV4Pj5JP/5S/rC26GuVNJlVOGRJjO+FMuBI
         gkLBSV2US3h+YZymOxOF0e2mRC1pSqA+9jKZNl8g+UPWKb0vRPRMOYNFJfIE81eHD47n
         9HhQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=JUMnAFa3ZHZVc8pfqqN5Y/htG8zVXTCDsG6+U+e4M1Q=;
        fh=hgOH+7c9+yae4IbXu5Xj0AdrYXtX5zIPhy8A5fEqbxc=;
        b=VLxdiucmq+we9lFLZphkJl4ljooK1IRI5M1EvW2BqVgL9211QeJYnhe9E59ucq/OsD
         uOEzs5Hf40Z4jV5A0NsITzWmKLaTBtdC4mmXnTCtlZ9XRUK9zoDfNCcuMAi0W+3ls3nx
         D0HGTtbO3AhrR36xfz97oQowF3C1xr5a5RNlaEZgXIwPft82amd+lZaySQNwpyATvjw7
         /kROcPhwndPeU4vgppZYI6e1ppCzJdeqUVk+vCXdejYN5xlw5fay/o6tyOV6qPEnwsM0
         fC2LGWkZ6avanRLGwUcj+EirVcv2RVNMKOOckTuSeXPUzrn7ZhLEP7Em68Oc7hVD9dYO
         jTJg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ZYXqgmAH;
       arc=pass (i=1);
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769189477; x=1769794277; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=JUMnAFa3ZHZVc8pfqqN5Y/htG8zVXTCDsG6+U+e4M1Q=;
        b=m35xNMjAdC6DbeOb2rJhP6UiJtd7g8Pxi4/EVqfEcCXmY7dV6YjdFOSxcQhSZRMNzI
         ejUZcBoSJXTr7qDACABAZfm84Qr67FhIqc6n+8q8nQLKd543wAZ5xqigXLCOYWMjO6ae
         9sr6JhuT/A8MVVgsVyGPgwMwkihmeH7Aq/pM5W5uC5JOzwUr3nej8VyYN5JAeyyNIYoE
         5j4LSzCwLcyzXU9kzCteL4I3vV5L9id+n5scWi+mn5ju/Elq3Sp/2brKFi4tk6rT/4KF
         PEblfwSZl0n/bKH+k4jg5PpRh5UXLpffRc1uAFeQnX8Ri+t8byhIp0GUiPygn3nEKfQa
         qb/g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1769189477; x=1769794277; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=JUMnAFa3ZHZVc8pfqqN5Y/htG8zVXTCDsG6+U+e4M1Q=;
        b=mVaW4AgKhfPCUoczRBQtqilltQ8O6K7Jcy3SnIxve7NA/cY/QQ1RVkgOS09Ot9tONZ
         PecoVzyrZRU0xpJvA33iyam4aq0gv+OjC/8ICXTDbE2MWyi5V/Fk+9P4OJ+f4UXhnaX4
         K9mSyE8N/4FLOahCH0tllT+zr+2MYZtipbIVCj43DRxwl5aG9eoip6Vl8x8XhieuvaGx
         Fv73zSNBzDfCtuRCVozjF8Fb2oLyiR7A567ScZsXlacdBFmVB69WkCk6Ac/4B4N3ssPN
         IGTwSsUL5WAuufLukETqYRc7ORBZzhKk8nGbe3TwbdKUNcZue++eKx9HOFzgJnSeD22x
         fdVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769189477; x=1769794277;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JUMnAFa3ZHZVc8pfqqN5Y/htG8zVXTCDsG6+U+e4M1Q=;
        b=pHXnpnysCr3gqzMdMsGauk/1HPif6YSXGRFYZ6oceIYlxZkMYuSeavMpJ3Ave40ca7
         qd0RyDg/3I07DHSghddLh1eL7yokMsrx3/dODJG/pEk+8pgBXNX0EJjozhmX1Xz38Ehl
         7kwlQIvBGr9K0HPytPhFryB+s9tKzzaHlzigLHItxnSL/EnUP7S7N1TLpx1ifkuIHJaz
         Wj3IzU3SGanUnc3Sd5NiuSG5ByivVynOWXrImYYNnhAjyw0O2/qoN+hfa8W3v6lH9dYF
         mpPPIVzNSv3I9SrQRgsWiSSdsXNvx+Xi/SlX0mI5+N7168X/rZAxwkU1D9ieYSa3O3Gi
         od0g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCU2oa1NwxgRiurdMgJJswKg/oDbmmY4MP8eMShKAvUjjAZTuQeOtnMEdakUJ1Lddqhl8so47g==@lfdr.de
X-Gm-Message-State: AOJu0YytvBlHRW9KBW0lN//MVN4VvTqfMebm7R9+LUIUS4e+HABS99eu
	NBIEvpwhyD+GM8SNLnJ/jVEr17Oo3qo5o7i3mYqNStd619/NMbmbNXcf
X-Received: by 2002:a05:6402:3481:b0:64f:d03a:9af4 with SMTP id 4fb4d7f45d1cf-6584874e42cmr3009254a12.3.1769189476799;
        Fri, 23 Jan 2026 09:31:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EyfFkXsS5fiJdXdbwISXJ60UkMeuge7bI51zi13q9xgg=="
Received: by 2002:a05:6402:10cc:b0:641:6555:a42d with SMTP id
 4fb4d7f45d1cf-65832d6d237ls2238966a12.1.-pod-prod-06-eu; Fri, 23 Jan 2026
 09:31:14 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCXixqGYxDTricpsXYz4zalP7Rx8P7fZA358meGh8cVaIYKBmmkiO9A5wd4UUl4Jww8MQxi2m3reefI=@googlegroups.com
X-Received: by 2002:a05:6402:354f:b0:658:1e06:df88 with SMTP id 4fb4d7f45d1cf-65848763767mr2621680a12.12.1769189474286;
        Fri, 23 Jan 2026 09:31:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769189474; cv=pass;
        d=google.com; s=arc-20240605;
        b=aHCAz1OFlr+o0Vq4dml4YF1lhw15uGweuNeixhZYhi3q0upRooeRMqNZlFMH3xSuvU
         Aloygg16r0+cPqBleRzOVjTkAPju4vneBcZWRP1lnuXMk1FuhAcGpobyhBQGyYHVvUKc
         8u0NDXDaEG2dfJ2zG9Z9sJ1yY+WlY+DgcScUCrLjXnn/n7mtTBYpBqH9lTa54w5kavQf
         a5/a/fvBdgB01608lgjHbGDKLmgvrwpfgFxNRvI6Ofzq5KkSBZ5UgijwMq8SbXqzqsTr
         TU2Z4uQWrfcRsaUxQ3SITcImob63mdaLoR2mIfNnZIrKRySirokwNgapXmqi+eP3AjpJ
         ARZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=//l0nEjTNRiO6ok8x5R3UO9HJXdIVnzS4jZFSqDgDdg=;
        fh=+7E2xftcY2MU2JdnU6nlcjh68Pkbbei5qwmdtR0PxdA=;
        b=JldLVQW3ATwGGjxfKa4tY5bO7td8Lf/9n+bOmG2UsnJoGUqtCWx+DEyvO1CyZVUNmi
         LlzeLeizwla4VWCO/o2zVRoTs6xkdRaB84t6uXtDwwj88ozZBx0vXmNOGhMvtwD6dPvs
         M2knIc0q2ynOGaktVLWWprI6iA8BSI3JBz9X3n+krlSktG/2Re3BsZOciq4e007qiu8D
         PkfpZBQJUsCsyAMapNtP1MeaaeP93Ac46ifWBjm1BUfzOlW95lExQJhCbJXcVKvescdw
         7lrB7J5Hq4ZZIyXhUKpX6wf6DNrTjhwp7qlw6XuTecgOKk6lhVeDNfuJ059uDOv1CTCJ
         91IQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ZYXqgmAH;
       arc=pass (i=1);
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42d.google.com (mail-wr1-x42d.google.com. [2a00:1450:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6584b3e7239si77941a12.2.2026.01.23.09.31.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 23 Jan 2026 09:31:14 -0800 (PST)
Received-SPF: pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) client-ip=2a00:1450:4864:20::42d;
Received: by mail-wr1-x42d.google.com with SMTP id ffacd0b85a97d-43590777e22so1504144f8f.3
        for <kasan-dev@googlegroups.com>; Fri, 23 Jan 2026 09:31:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769189474; cv=none;
        d=google.com; s=arc-20240605;
        b=KfyplvraKpIePp79KJA+nJUsulg6EXNHOpnr6hTOlbxj/n+w5UoDIplj8J7Vv22DGn
         mGGeEATZ4IrtgiuYIMI8pdz4UquwA8HYgZvFuRTNuUoXdYFLNDKI7X8D6r3886cpEZtY
         LsEs8OrhCTEfNdyycmKSQJctg5kka6Abyq/p2NHscyTYVR0TtBUgDA2KcvtAiEQvcrV9
         uizQSayzcI4P+elym+Atz7dLHZiHMnsCvpAMp3uOIhyxjMMyISQM736wkcq2PrFyo5u5
         T+AG6Sp5FNeWowXN4AZMdVMv6r+iFkPIBAETTdrlAmyNe7jhZvfuphfERt0T11PwA5DS
         sr4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=//l0nEjTNRiO6ok8x5R3UO9HJXdIVnzS4jZFSqDgDdg=;
        fh=+7E2xftcY2MU2JdnU6nlcjh68Pkbbei5qwmdtR0PxdA=;
        b=hLBrxE4iS3sBrizL7MdOkE+mrOeYrBBIVzNLKgos+Cgh6vZOzG4MM+GCVvkm4rjSdp
         Na+xWX4tSUqROdCPEvjCXyBhf/mkjaNbR9oswvHOJ4eTjPOyGrXLj6tGUmAaQ1Q+i0QA
         8qH/GcWGouNsyvOnasGS85+0c5yq7BOH5+QC0mQSsZ+LlLkxoVL8dQfRXg+QToQ9SYj5
         0F30yZ/bna0AWxqsCIMNPc8dzf5Fu7BpwLbZvSmp/e9CjN0fKHIYvhdVkwN+PZpSWu0J
         AuedLErDzYmX1Y0SJKISpjZDxTyp3H5u7Cyhc+Mzv4f8QvGzqsRgSxYnUIh1vs7c5xhg
         impA==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCXqHDdPHKYuHnN1ZmVuluL2PPVnGCD/TYTFQMs/hOZreLdCCO2JvvBD57WmNRTlht4UwqrEt01ftzc=@googlegroups.com
X-Gm-Gg: AZuq6aJL4ckZcOCVjhZuxy7Y5jcPsjgyzWwRBSGVUu2xZUu8hrOTx3ExDzRhjjNzGdW
	dk64VyCfVNNUCxrUScVE6IWc6+jydf6BvwE60aK1DCPfUe17ucyUacq+MhO/fmvrUjbQn1k73q6
	p8f8SNagC7lf7uwl/gNxQIRo2S6OAd81wZM9kn9D+AY8UAnhUn2OF73Yfc7rbPEFCZTxYZm+KHH
	miZRIXnHv95P4KhuBdQJbZbRTbwuUVaGDA9nDAFN5/PLqNCSZksoqXk9PWvGda6q8GXQDQl0bAi
	g3UWvIiO4hB/CIWpfWqH99sn5qncyL805FdlHRZpr/KGtEQCYK/ewFzFNNW3/hjhTjPMxVdM
X-Received: by 2002:a05:6000:2dc4:b0:429:b751:7935 with SMTP id
 ffacd0b85a97d-435b16280damr6748411f8f.56.1769189473665; Fri, 23 Jan 2026
 09:31:13 -0800 (PST)
MIME-Version: 1.0
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz> <20260123-sheaves-for-all-v4-14-041323d506f7@suse.cz>
In-Reply-To: <20260123-sheaves-for-all-v4-14-041323d506f7@suse.cz>
From: Alexei Starovoitov <alexei.starovoitov@gmail.com>
Date: Fri, 23 Jan 2026 09:31:01 -0800
X-Gm-Features: AZwV_QgSD9SUVQI9Y0Yihip1NN5Dune2qBBleSwBNI5G1-MsD4RlJ98R8TtLbTY
Message-ID: <CAADnVQJi09vC6Y-jb8mCRfj-OrECvSTMQ_XL2OE8W-B4zPwGSw@mail.gmail.com>
Subject: Re: [PATCH v4 14/22] slab: remove defer_deactivate_slab()
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>, 
	Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>, 
	Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, 
	"Liam R. Howlett" <Liam.Howlett@oracle.com>, Suren Baghdasaryan <surenb@google.com>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Alexei Starovoitov <ast@kernel.org>, linux-mm <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>, 
	"open list:Real-time Linux (PREEMPT_RT):Keyword:PREEMPT_RT" <linux-rt-devel@lists.linux.dev>, bpf <bpf@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alexei.starovoitov@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ZYXqgmAH;       arc=pass
 (i=1);       spf=pass (google.com: domain of alexei.starovoitov@gmail.com
 designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-2.21 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[gmail.com,none];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601,gmail.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TO_DN_ALL(0.00)[];
	TAGGED_FROM(0.00)[bncBCUY5FXDWACRBZHAZ3FQMGQEWWPMSEY];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	RCVD_COUNT_THREE(0.00)[4];
	MIME_TRACE(0.00)[0:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[18];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	FREEMAIL_FROM(0.00)[gmail.com];
	NEURAL_HAM(-0.00)[-0.999];
	FROM_NEQ_ENVFROM(0.00)[alexeistarovoitov@gmail.com,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+,gmail.com:+];
	MID_RHS_MATCH_FROMTLD(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail.gmail.com:mid,suse.cz:email,oracle.com:email]
X-Rspamd-Queue-Id: DDCE379097
X-Rspamd-Action: no action

On Thu, Jan 22, 2026 at 10:53=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> w=
rote:
>
> There are no more cpu slabs so we don't need their deferred
> deactivation. The function is now only used from places where we
> allocate a new slab but then can't spin on node list_lock to put it on
> the partial list. Instead of the deferred action we can free it directly
> via __free_slab(), we just need to tell it to use _nolock() freeing of
> the underlying pages and take care of the accounting.
>
> Since free_frozen_pages_nolock() variant does not yet exist for code
> outside of the page allocator, create it as a trivial wrapper for
> __free_frozen_pages(..., FPI_TRYLOCK).
>
> Reviewed-by: Harry Yoo <harry.yoo@oracle.com>
> Reviewed-by: Hao Li <hao.li@linux.dev>
> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Acked-by: Alexei Starovoitov <ast@kernel.org>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AADnVQJi09vC6Y-jb8mCRfj-OrECvSTMQ_XL2OE8W-B4zPwGSw%40mail.gmail.com.
