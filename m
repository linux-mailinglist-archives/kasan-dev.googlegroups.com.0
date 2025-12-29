Return-Path: <kasan-dev+bncBAABBNH2Y7FAMGQENIWNXZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7292FCE5E60
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Dec 2025 05:01:58 +0100 (CET)
Received: by mail-ot1-x33b.google.com with SMTP id 46e09a7af769-7caf66b2866sf21252286a34.3
        for <lists+kasan-dev@lfdr.de>; Sun, 28 Dec 2025 20:01:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766980917; cv=pass;
        d=google.com; s=arc-20240605;
        b=OC7s3PfJfBDCBqgoQf28VhBfXKSJ7ejsZM3yeEsB4XLqEJejItjO/1jTYAcjfWLWZh
         kq7yL9zQ3Oy7iKUDmlb8ITpzWuM0jgoW0Kto3Gz1ah/9fScwKRd5HkCDDKvKIbtp2aDq
         Ux8c/vAfcuEwkA08Jh9vptBs3w6HKMYR0rvR9BJaOfj8AUqW4NK+lOTb3/GmdSepOwO4
         8KRXIb08ysNOD6LgFA+/4/EQJAwS1fXAt7exIH6vN6MreJdlQMLh6xPZPyDtSMEEgIBh
         PweFmIByJnKe4O3GwluSkdEWYGJlY2s6ecVvvO2QhG22ygFcf2VyvLs4FhUYtPfyGkq/
         3Idg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=ks4DySojZxkX9xh65EvphvUzRXVIOFfk1E8FmEYk3eQ=;
        fh=sg6/BAdWCIBgnDmeNXnOwbf29ho0JRSrKPYff+6wf/8=;
        b=BqgzQ5/vf8abvpBStKGDwipFc3B6M3ntLoo1RZ/DWCECmswZfXtwR7dIWkWRhlxG7p
         5LdG4l/uQ1BhofVbLzqK1uaM9iTCgRdQjA68ryele7SjmuDTDCoaEoH1ECBL1pPsXsXD
         d5Z3WGs3iI7q979kI0vgU8CfzRDia0GA/4fcViHfrhZbefTPZWwoI6U82KCh145RmXhf
         /cDa2e908Glp+XZleN4YFwgM4dTCJPbdhOvDb2wYjAFEd719Fr5hxyBLbFxgbVwPeR+w
         3N1F7eCurnanRcdrPgiTe9R25NhNegPobj56Byhl+/VDA8pjqVF/+u+rgedJO4lbkBLE
         Javg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yuanlinyu@honor.com designates 81.70.206.69 as permitted sender) smtp.mailfrom=yuanlinyu@honor.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=honor.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766980917; x=1767585717; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ks4DySojZxkX9xh65EvphvUzRXVIOFfk1E8FmEYk3eQ=;
        b=XqbDzc+cOysAtAUvVn+ABS+QdpqpaPHVSjjd5bh9tz8jkidvkM384VySHl+PGbzLLG
         jrXh0xSmcdnyX/XG7weWmRLupdwzfILCsMtf8SYbV9k78S8Wydm9PL0aRnz/1n1JzCBy
         bFZudfECEKtvCvMPdA1+7KlRk3r7qfOi8PTblp4XuvX2EK3qXA/3gaa10Jmof77/kkEh
         U8ANdXOa5wUrndtV40X+pRFk0OENwQwjepgPYc9C3al95R8sW9WgkYRYwaxqpKxKWhOl
         BhztwnO0AhAKyLxZ95TQC4xEwcGrsV+YO8NWtOpbZJ5oJqnVicKMWvZ7mMRmxle7bU3v
         gXqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766980917; x=1767585717;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ks4DySojZxkX9xh65EvphvUzRXVIOFfk1E8FmEYk3eQ=;
        b=eAdtO8Fy7aIqMgLOqsg3PgIRZAY0OAslVRejdtZNMo07jS1t5ZUUlPCXp7hd0LbVnH
         JqcaHytz5k22xUc/hjxeDbAunX7nKi2CTd+4cedk4Ecre/J4lItE26ihdjOLFjyr7+/o
         uCTjsbVf683qoIQX47FR8QFhm48byw2YzY5njgNz4hEhB1kXWx4Qfr9s9beY7WTebZb1
         KygtcBOvxi7Ll5sE97zXRDnX+7bPoTgKVy0K+CRp6q6cKUWSKwKNn7GGiEx/1JNsldLL
         fwhU29dzIjnR1Tcms0L2NlNSUvUzTokOSxVoAWrutdJvUM98Ta4DMTcsQqoaY2eINSSL
         gv2w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUwR4i7WSVSl4zBy01Im7HtPukEnr/ms6rhz3JlyeZJtb2G7DQfeoRX4GQHBQHwnOpqDz0WwQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz+zqGEqxantEr3ZcsS6YI7gkyWznlPljNEaq9m2oU/mO2OsfSn
	LNtx4nPE5LAWVWBfZjdii4awYojBiblbK84yhvfcqNH1aMPodLvIrIJR
X-Google-Smtp-Source: AGHT+IF1pS3EP/ez3kRpM5DD+dDau0L02xpoCtD8JqW2Y/ES5AgxUyJEc5oC3S3zR74SVL2aM8KSDw==
X-Received: by 2002:a05:6820:4918:b0:65d:1082:e2c5 with SMTP id 006d021491bc7-65d1082e64emr8783024eaf.68.1766980916791;
        Sun, 28 Dec 2025 20:01:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWaRH5QsjMS5LcCB3VvQj9cJY7zmLNnTYKHiQXt65OYMBg=="
Received: by 2002:a4a:ddcb:0:b0:657:5773:7b1d with SMTP id 006d021491bc7-65d1d25b029ls3402544eaf.2.-pod-prod-05-us;
 Sun, 28 Dec 2025 20:01:56 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWtaVosP+KmT+cxftAydNw2jIGJ0DWlSl5ofqJXIbvTj+I5MWVNPGAwXxVB2RpjikryCjphmFZ3f5w=@googlegroups.com
X-Received: by 2002:a05:6830:4119:b0:7c6:a2da:ce4b with SMTP id 46e09a7af769-7cc668a4bb0mr15626547a34.5.1766980916102;
        Sun, 28 Dec 2025 20:01:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766980916; cv=none;
        d=google.com; s=arc-20240605;
        b=jAR2PSP9gaf0at/wWb0PrQlQLk/zrEweQRP8rYqTF8mnR9dNAKTe/tgiFTBkksVpOX
         vbT4ck3A/uEgZQjC75PAmc4mjnSAYQXPdVLc43v1tb8+1XqUL5o+d5KcuHopGYfHXr2J
         72zmFtk53WWp3mpxOCCZ524bzXj9aZ/Dr3Q7vHg0zv4bCsM0PnqSxkaPJJ1xmD6V19FS
         l2+uxD/mDOOsIUDRlV/wiUYK/Rm4P0vRgHC8dDoWBqs8TfyDbcuhBGwehDsPXYMAcShT
         w7mZXYrIRW9eMjiWWzF3pODQJWovvnJ6nfFeJL6j0tQdJOuyX1sLCOr0u2kj504Rq31f
         C+sg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from;
        bh=rojuF6qs0MzToAaFXa+KuXKawYXFL2AL5udxghRv4cg=;
        fh=sRLLPD1NR0EEBTnxwxNZlNZHRxniOboIlZTQ47sl21w=;
        b=lnrirtx2WYZ0oE9OOwoNHHZ/MTCwC5eK/aE22UymZAik6HLsb3/JoDo7kHJNuOcuch
         7H3nMA9Hr6A85lgTcgSF3Iu2yiU4nUXJg++QDoUwqpbrahL2ENIk2MkiUw0vcMD5T0PS
         kvUMk56XgwwM1yPf2x2NHQltWWnPd6vOJ5z5D4WOqbJPexbBA+7kl5ZKN9OwE0quw70m
         GRGUL7OeeopQprPwxYzwGOdrdV977+9YeBB0QYVTRWWAyetc1/IQ0IfW3P2Lg3PU2FNA
         nort3GXFPGRFIrZ9PQNf66GWNBkFrymqD74oZJ80oGeaDmTSaTv3xbFjqWG6KLv/ECQ7
         MKsw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yuanlinyu@honor.com designates 81.70.206.69 as permitted sender) smtp.mailfrom=yuanlinyu@honor.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=honor.com
Received: from mta20.hihonor.com (mta20.hihonor.com. [81.70.206.69])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7cc667b5952si1971769a34.3.2025.12.28.20.01.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 28 Dec 2025 20:01:56 -0800 (PST)
Received-SPF: pass (google.com: domain of yuanlinyu@honor.com designates 81.70.206.69 as permitted sender) client-ip=81.70.206.69;
Received: from w003.hihonor.com (unknown [10.68.17.88])
	by mta20.hihonor.com (SkyGuard) with ESMTPS id 4dfjBy5jppzYlJgm;
	Mon, 29 Dec 2025 11:59:06 +0800 (CST)
Received: from w025.hihonor.com (10.68.28.69) by w003.hihonor.com
 (10.68.17.88) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.2562.27; Mon, 29 Dec
 2025 12:01:46 +0800
Received: from w025.hihonor.com (10.68.28.69) by w025.hihonor.com
 (10.68.28.69) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.2562.27; Mon, 29 Dec
 2025 12:01:45 +0800
Received: from w025.hihonor.com ([fe80::5a3b:9b85:bbde:73b9]) by
 w025.hihonor.com ([fe80::5a3b:9b85:bbde:73b9%14]) with mapi id
 15.02.2562.027; Mon, 29 Dec 2025 12:01:45 +0800
From: yuanlinyu <yuanlinyu@honor.com>
To: Marco Elver <elver@google.com>
CC: Alexander Potapenko <glider@google.com>, Dmitry Vyukov
	<dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, Huacai Chen
	<chenhuacai@kernel.org>, WANG Xuerui <kernel@xen0n.name>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>, "loongarch@lists.linux.dev"
	<loongarch@lists.linux.dev>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>
Subject: RE: [PATCH v2 2/2] kfence: allow change number of object by early
 parameter
Thread-Topic: [PATCH v2 2/2] kfence: allow change number of object by early
 parameter
Thread-Index: AQHcb+kJOevioCwokUWRSuHGy2xym7UmkpaAgACVZ/D//4LNgIARZBYw
Date: Mon, 29 Dec 2025 04:01:45 +0000
Message-ID: <2ff11f959e78405088865c6d61535bfc@honor.com>
References: <20251218063916.1433615-1-yuanlinyu@honor.com>
 <20251218063916.1433615-3-yuanlinyu@honor.com>
 <aUPB18Xeh1BhF9GS@elver.google.com>
 <7334df3287534327a3e4a09c5c8d9432@honor.com>
 <CANpmjNMmiXjifpc9LdCVi5jzzKU3sgb0iJn7P7TMFMNqDH7TbA@mail.gmail.com>
In-Reply-To: <CANpmjNMmiXjifpc9LdCVi5jzzKU3sgb0iJn7P7TMFMNqDH7TbA@mail.gmail.com>
Accept-Language: zh-CN, en-US
Content-Language: zh-CN
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-originating-ip: [10.165.1.160]
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
X-Original-Sender: yuanlinyu@honor.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yuanlinyu@honor.com designates 81.70.206.69 as
 permitted sender) smtp.mailfrom=yuanlinyu@honor.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=honor.com
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

> From: Marco Elver <elver@google.com>
> Sent: Thursday, December 18, 2025 6:24 PM
> To: yuanlinyu <yuanlinyu@honor.com>
> Cc: Alexander Potapenko <glider@google.com>; Dmitry Vyukov
> <dvyukov@google.com>; Andrew Morton <akpm@linux-foundation.org>;
> Huacai Chen <chenhuacai@kernel.org>; WANG Xuerui <kernel@xen0n.name>;
> kasan-dev@googlegroups.com; linux-mm@kvack.org; loongarch@lists.linux.dev;
> linux-kernel@vger.kernel.org
> Subject: Re: [PATCH v2 2/2] kfence: allow change number of object by early
> parameter


> > Could you share the better design idea ?
> 
> Hot-patchable constants, similar to static branches/jump labels. This
> had been discussed in the past (can't find the link now), but it's not
> trivial to implement unfortunately.
> 

Hi Marco,

If you have concern about one more global, 

how about below code ?

/* The pool of pages used for guard pages and objects with number of objects at lower bits . */
unsigned long __kfence_pool_objects __read_mostly;

static __always_inline bool is_kfence_address(const void *addr)
{
	return unlikely((unsigned long)((char *)addr - KFENCE_POOL_ADDR) < KFENCE_POOL_LEN && __kfence_pool_objects);
}

It may generate one or two more instruction when compare with original patch.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2ff11f959e78405088865c6d61535bfc%40honor.com.
