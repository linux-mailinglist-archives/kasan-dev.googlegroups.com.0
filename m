Return-Path: <kasan-dev+bncBCMPTDOCVYOBBXHGWS4AMGQEQ2SPCKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 667FE99D0AA
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 17:06:06 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-45f2775733bsf115195681cf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 08:06:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728918365; cv=pass;
        d=google.com; s=arc-20240605;
        b=kC0jW0E4vN4hPKg0g7ZphXWDMOkhcXWGr+874nuyjsNnVrpJdFwQmwyTnNDXwoI6q8
         mp+J4sed+XexDT9bR5nnx5d2KcMmaT4gQgRbAl7m5IBwCyz2WkKkx26RR0kDBSRiFMi5
         mavzw4tAqsVNITdNSdoFrDbZpTIKixSrqslt06iXa/OtwZtTlSoFEI95gdmeZ92U6+Mm
         qrjekCAL/mcp1dJPvWHJB3GSOUqGf6/oTi3y3QoZ5aVGIl+WYiFZP1bKQvEUe7xvx+iy
         0Yyzj8kQLIm8RsZZcA6L6MGB1ca3Ojm29OBVfeJkRE+wSPfFvYOpnjU/2aBJlLpyshwU
         XMsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature
         :dkim-signature;
        bh=FabGepafo3wcCsUI0KcsPd1uW2EZd70u0RwGLLSJjM0=;
        fh=fJg1a0pTZXfoBcNvgNpiIKkFYV6D0zxDO2JE+69BiHo=;
        b=C/iwJL07LHOOvDJADZmVb0w8kc743oKMwvTIaBRwJJpF+RBjZ7FjEojNOSS6UlSYbg
         wxa/3zZIsoRWEkfGT6/2KDP1kYULKafJGgHSPl+q3xflL2jJ1OokqlTV6czBJt7Yc3lU
         LjpJ+5oou64vesnYHEIXUlerVXPxhiq2C7U2wPPlMZnssr9+PKTbOluCztPiMFTq5xhp
         qsSHLZKbHdir5tbA2qJbNI6BhXJGnWcD/Q9oVRljKj7k4nrorsE87hQcncRev3R7QYoV
         Z4Slfi4ckIpmS7Lglwct5fOilf0cIqGWxAP/cE+MxlFPxxb4gEJPeXVcB8DGV9mG2vkK
         FHeg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QFFJTBSs;
       spf=pass (google.com: domain of niharchaithanya@gmail.com designates 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=niharchaithanya@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728918365; x=1729523165; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=FabGepafo3wcCsUI0KcsPd1uW2EZd70u0RwGLLSJjM0=;
        b=DpuvquEZtv8AvlZp07oTOLdM7tbR3WLoT4CoiIHAIkKtFFwIsT2iVuBxh3gPP5ateD
         Tk5naHLlsfm2940PpisT1aHHe9gdO7dm5qHnSO/LX1EP0+rNzXmAorIqp1MHLtZcXMSS
         lrBfdIawGN+kw6scmuVyst90gVJ1kl2Auv1SdHvsGs5uiKniW+bcgPYw45FGDwFer+JL
         63ChTloLbZK358purp63GXnjoruhdVLrKLVykb/VIpauul+8depJCd2K5wKMv2ajgo6i
         ecc4lQaF0QO4x8w93jHKq2mpAZPLPlEQyCynpSeH9H+4o8Tp8is37F38o7Tr6UWISGq4
         4RNw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728918365; x=1729523165; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=FabGepafo3wcCsUI0KcsPd1uW2EZd70u0RwGLLSJjM0=;
        b=G0OoqQzN1g9w/AgsHJfTA/lkGPMVHdub54c5+3dEIvcVsSx35epHV6o1x8JWRLGg0v
         Vnv+Gay6HtVn8deyiWerHsTAFJz05j6bQpmxj27epdToHzQQpliBJLJRaRw8461tzXnE
         KnZJC7Hr2Lu0+vj85MrWM2nC0LL3EwHIUSGqvioF+L2JqZ4qYvIp1rEr8lFgNSGXcIcm
         H7FgveQBXcNbbIXakfk0iBd/g5vv8+qgUVOawi/Z/928HwKaD2mfIzDOxgdXuxiBm5ZC
         Gkd7dA0LJ5uLbOyQ2WHw0EgXCQZLTZ1daDiIDx89iyLVc3DYdMwjPqXNESG1j+n+JRYP
         qtuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728918365; x=1729523165;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=FabGepafo3wcCsUI0KcsPd1uW2EZd70u0RwGLLSJjM0=;
        b=J0h5y/eZP8yj0pyxsx7Xc/4tOp64mfLkVBhCKYS5tdDBg9/o3ae322D+ntn+rMwB6D
         CgQWFiJW9AnsAkoIGEBzY77JEp7I2v67WeYX95o9CXCtTj3V9Mei6URx3dv6p6xkVDyI
         56ioxXurYpM3oyEP3f9lhEQMQlVn3xk+qWEdrhvIq54QIO7G9gxrxIKJz/dGOsuLuOQ3
         fSOrjANeNToFPLqNa3fYrDpM/CLRjTEAF/SbjzTMz+/9WhaIfMTLJfByjLjFmPusG8q4
         32Wh9G1y6NuxCdhHqe+8Bq/xhD4Uzm6V2EAxMxkkXbHezexPc7+dc/RjC1gZqHdb2+/4
         5FSw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVL9ca72Z8FA4nCp/vtJqSJfCc1PwyUuDy07X25mF/IO3xk0m4HKIsiVe+iLSDBkoo/FNp6Ig==@lfdr.de
X-Gm-Message-State: AOJu0YwwSISTMFsb5L8sci5hJENP6nq2WyD8+fGGwcUekVkwr7MqcjRY
	R38jw78iNHNSrTnnjqLIKS+UIiiiABTP8Njh27mpuvM3Bxs2NY/2
X-Google-Smtp-Source: AGHT+IFr/cyejsG4HfejS73mVNjSvgaGfVsZ+3UmQIB1X82DNj1z9pJcaTMHyJSOLIUXt/jxeQMK3Q==
X-Received: by 2002:a05:622a:1307:b0:458:2182:b07a with SMTP id d75a77b69052e-4604bbb91ffmr199748061cf.18.1728918364915;
        Mon, 14 Oct 2024 08:06:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5755:0:b0:447:f206:4e7c with SMTP id d75a77b69052e-4603fd6ba83ls71809191cf.2.-pod-prod-07-us;
 Mon, 14 Oct 2024 08:06:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVW+IAWIc9g4VPADws5JHi5o9UsHmupqjPgbfmOVkv6KTl7I6NTL6DgwZHKjBc9meuj3RU/HJnYZ8E=@googlegroups.com
X-Received: by 2002:a05:620a:450c:b0:7af:ceed:1a4a with SMTP id af79cd13be357-7b11a3a2235mr2112517785a.43.1728918363219;
        Mon, 14 Oct 2024 08:06:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728918363; cv=none;
        d=google.com; s=arc-20240605;
        b=O7SrzJiIwKO2VXtknHjF7rWp4cUIxZMSvaxNGZN71kO2zBrZYaMLNqJOY5+keBaiXj
         TSYh+nYNXVXnjpDUm3HqNmqsVijwLT7MX4RRJz8WwBpoSMvJD21PeJx8eOuCJPaVTIkG
         MmevVvjjEoIPw9MYgPWxv6hyX0UE7AR2SuSTly2H0Cz+5VQXjDBlkO0QViGQtnXZnl/L
         gkYfs6wzRrjMIhd8T9MyFW0AGilPfcri2mzquOJhpmcvAmX8EEWmf01ILgzc6sXiTCV4
         4vbHOogLqqeCeBRE5wuhZHL4g21pNf3sHz8ezTZP2WCkQloDRNIdicuZGPxMmkeO2COB
         G/6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=Xc/MY3utwq++TumE+kg0BgRHpsSHoagJmtSGPnXPBdw=;
        fh=2KP+j9JyrqMzAR+/VRTy4RkM95qCEmFf7qKRz8VDzgc=;
        b=WmYaKQaeXrs9tDo//xiFWexkODgm56oZNH+/UJlAro9XnMNTfJiYW7KWTl9tdWs1sV
         D73GAqCNBHsIxBRXppqjJttuiV885UfVONJqkVMHyVAxd0sVzFhOPK0MIZ50nbR2eP6N
         Jy/3UF1nQWWr6CTYVIK7u7j6JT0zF7b8c62pjeiQA6AHEeNvdq4U2lYVP2yB2sArzUxs
         GKE+tG+Eymk3E09Y1SiqamZFNyzsScIfuIflRxOij42Y2GSCVJOc9bjyc85YhmUHz9kv
         8pzpcm9iv/aScDIkPM9Tev2TuQZ32qFEDaVHAaF8U35F4bxlWobbyXRlyY0KbHUD7B5m
         J9Cg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QFFJTBSs;
       spf=pass (google.com: domain of niharchaithanya@gmail.com designates 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=niharchaithanya@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1032.google.com (mail-pj1-x1032.google.com. [2607:f8b0:4864:20::1032])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7b114987ca0si38056785a.4.2024.10.14.08.06.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Oct 2024 08:06:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of niharchaithanya@gmail.com designates 2607:f8b0:4864:20::1032 as permitted sender) client-ip=2607:f8b0:4864:20::1032;
Received: by mail-pj1-x1032.google.com with SMTP id 98e67ed59e1d1-2e2ab5bbc01so783323a91.2
        for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2024 08:06:03 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX5UCde6Xd2MXZAIm/3th2m6GeGTapR7/BQcsKHb0eYdb9dlEmz2wkzeP8N4TZvG7JBRVxsAIGYoZw=@googlegroups.com
X-Received: by 2002:a17:90a:7c0b:b0:2e2:d562:6b42 with SMTP id 98e67ed59e1d1-2e2f0a2ab4fmr5981947a91.3.1728918362003;
        Mon, 14 Oct 2024 08:06:02 -0700 (PDT)
Received: from [192.168.1.17] ([171.76.87.218])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-2e2e922a8dcsm3538236a91.0.2024.10.14.08.05.58
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Oct 2024 08:06:01 -0700 (PDT)
Message-ID: <ef2eac3f-5a26-4397-9bcd-e0d7d652b282@gmail.com>
Date: Mon, 14 Oct 2024 20:35:56 +0530
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2] kasan: add kunit tests for kmalloc_track_caller,
 kmalloc_node_track_caller
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: ryabinin.a.a@gmail.com, dvyukov@google.com, skhan@linuxfoundation.org,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
References: <20241014041130.1768674-1-niharchaithanya@gmail.com>
 <CA+fCnZex_+2JVfUgAepbWm+TRzwMNkje6cXhCE_xEDesTq1Zfw@mail.gmail.com>
Content-Language: en-US
From: Nihar Chaithanya <niharchaithanya@gmail.com>
In-Reply-To: <CA+fCnZex_+2JVfUgAepbWm+TRzwMNkje6cXhCE_xEDesTq1Zfw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: niharchaithanya@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=QFFJTBSs;       spf=pass
 (google.com: domain of niharchaithanya@gmail.com designates
 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=niharchaithanya@gmail.com;
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


On 14/10/24 18:19, Andrey Konovalov wrote:
> On Mon, Oct 14, 2024 at 6:32=E2=80=AFAM Nihar Chaithanya
> <niharchaithanya@gmail.com> wrote:
>> The Kunit tests for kmalloc_track_caller and kmalloc_node_track_caller
>> were missing in kasan_test_c.c, which check that these functions poison
>> the memory properly.
>>
>> Add a Kunit test:
>> -> kmalloc_tracker_caller_oob_right(): This includes out-of-bounds
>>     access test for kmalloc_track_caller and kmalloc_node_track_caller.
>>
>> Signed-off-by: Nihar Chaithanya <niharchaithanya@gmail.com>
>> Fixes: https://bugzilla.kernel.org/show_bug.cgi?id=3D216509
>> ---
>> v1->v2: Simplified the three separate out-of-bounds tests to a single te=
st for
>> kmalloc_track_caller.
>>
>> Link to v1: https://lore.kernel.org/all/20241013172912.1047136-1-niharch=
aithanya@gmail.com/
>>
>>   mm/kasan/kasan_test_c.c | 32 ++++++++++++++++++++++++++++++++
>>   1 file changed, 32 insertions(+)
>>
>> diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
>> index a181e4780d9d..62efc1ee9612 100644
>> --- a/mm/kasan/kasan_test_c.c
>> +++ b/mm/kasan/kasan_test_c.c
>> @@ -213,6 +213,37 @@ static void kmalloc_node_oob_right(struct kunit *te=
st)
>>          kfree(ptr);
>>   }
>>
>> +static void kmalloc_track_caller_oob_right(struct kunit *test)
>> +{
>> +       char *ptr;
>> +       size_t size =3D 128 - KASAN_GRANULE_SIZE;
>> +
>> +       /*
>> +        * Check that KASAN detects out-of-bounds access for object allo=
cated via
>> +        * kmalloc_track_caller().
>> +        */
>> +       ptr =3D kmalloc_track_caller(size, GFP_KERNEL);
>> +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>> +
>> +       OPTIMIZER_HIDE_VAR(ptr);
>> +       KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] =3D 'y');
>> +
>> +       kfree(ptr);
>> +
>> +       /*
>> +        * Check that KASAN detects out-of-bounds access for object allo=
cated via
>> +        * kmalloc_node_track_caller().
>> +        */
>> +       size =3D 4096;
>> +       ptr =3D kmalloc_node_track_caller(size, GFP_KERNEL, 0);
>> +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>> +
>> +       OPTIMIZER_HIDE_VAR(ptr);
>> +       KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] =3D 'y');
> What you had here before (ptr[0] =3D ptr[size]) was better. ptr[size] =3D
> 'y' with size =3D=3D 4096 does an out-of-bounds write access, which
> corrupts uncontrolled memory for the tag-based KASAN modes, which do
> not use redzones. We try to avoid corrupting memory in KASAN tests, as
> the kernel might crash otherwise before all tests complete.
>
> So let's either change this back to ptr[0] =3D ptr[size] or just reuse
> the same size for both test cases (or does kmalloc_node_track_caller
> require size >=3D 4K?).

We can reuse the same test for both cases without changing the size, I ran
the test without changing the size (i.e., size =3D=3D 128 - KASAN_GRANULE_S=
IZE),
the KASAN report was generated. I found instances (drm/tiny) where the size
passed to the kmalloc_node_track_caller is < 4k.

>> +
>> +       kfree(ptr);
>> +}
>> +
>>   /*
>>    * Check that KASAN detects an out-of-bounds access for a big object a=
llocated
>>    * via kmalloc(). But not as big as to trigger the page_alloc fallback=
.
>> @@ -1958,6 +1989,7 @@ static struct kunit_case kasan_kunit_test_cases[] =
=3D {
>>          KUNIT_CASE(kmalloc_oob_right),
>>          KUNIT_CASE(kmalloc_oob_left),
>>          KUNIT_CASE(kmalloc_node_oob_right),
>> +       KUNIT_CASE(kmalloc_track_caller_oob_right),
>>          KUNIT_CASE(kmalloc_big_oob_right),
>>          KUNIT_CASE(kmalloc_large_oob_right),
>>          KUNIT_CASE(kmalloc_large_uaf),
>> --
>> 2.34.1
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ef2eac3f-5a26-4397-9bcd-e0d7d652b282%40gmail.com.
