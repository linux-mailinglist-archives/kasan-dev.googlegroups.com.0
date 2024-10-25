Return-Path: <kasan-dev+bncBCMPTDOCVYOBB7EN5S4AMGQE7PJB6UI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 89D1D9AF79F
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Oct 2024 04:48:30 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-3a3b2aee1a3sf14377815ab.1
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Oct 2024 19:48:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729824509; cv=pass;
        d=google.com; s=arc-20240605;
        b=eCbbZYen0e3Lx7LYGoVK6trBcCMy14vya2yu3Rz4RyRa84QHAT6+uQDMW56UlYG7N1
         JePBi905u7L0qQ9OavjhsutbWrVbZUYtajXkBvQ4p6ocpksxeG3/xlFNX17E6OD68Z/r
         QPD/Ec+lsxpAufBz9bIgdZSPmVFobGeJf9jAr5lV+TUnvlzvqxMWY6HF9OTJWMWihViv
         2t91NjkZV6B8gOGCjdX5BDlRVfjjuPih/0VHc5dGecX1DqvrhFJOuxsoo1vTg5s24ez2
         rnIPJnNfGZnn6BLFn5d+ty6+9AAlOusWag+dj+Xrm+caozVlzhrwzvNp9yXUZ6tgODlT
         uK3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature
         :dkim-signature;
        bh=Bhuf5SWebCkF1uVsLexTRTrl1uUVh0OSNA6SyDUwTAs=;
        fh=wHnyWpY7ameLYtVezPD4s4+A3aopcssni4B25m63YF8=;
        b=dONBSTyqMiZMi3ZXQZjSYmFajCPCj0waJ4eFxQ4yUZJ1BWsVWV1PfgrhWSFZvk5T3J
         GzK6TcXpjn3GHP7YWY+DlfSD7lKBHo6n0y71bB700eqw2tHCZ0YRsirPs7hZrbs0mK3z
         JiVH7Qc9XrjiHc60sq6DK3xszKzvIinlrJCAX9MgFXgPvHlXD47N3tjGTnbUgcRFwboX
         9LJyjeoG4eempu66zR7ZT1qZ6OFiHSueauLp7rfzwXmOHVm8rK5yWZsOGddio7gaw+Gn
         8msYWWgrjGzYK/set0Okn+zaYKJK5e7RkZOoPtzR2fACdudp6Tjk6SiULWZZ15cg2XaB
         xMcw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=fblJALRk;
       spf=pass (google.com: domain of niharchaithanya@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=niharchaithanya@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729824509; x=1730429309; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Bhuf5SWebCkF1uVsLexTRTrl1uUVh0OSNA6SyDUwTAs=;
        b=pznfxTkyHirut1qQmXGwthh+FgpGjVkgRGxcXMu8DIPYNHHEbfS6h7Fi/sZpn0nlJL
         EZHCuhPP+kvMnlwkJU9A4qOjxlbCIo+4+FEIG+nkHufw213N3rnaGK0keQSUAqK+rUaU
         yY9hKEfxIJ7bv1dtUq+fcE1AMq0WNkRCGZkLlYRNKSBcotDnqlPx6OKutOkB2lKuQ/SG
         ckgphZHYRYzILxwIQCtHetCMmRrnVdKcOxfOF6CqZ3VNJFiNmfR4iDjKq6nZRXWCfEp2
         ETefQCGBxlGL7gDl/ZpulO4AvDETPcpqvG7Cq0v7St4b5bQhop/gRWJuJiRmIXNs3INJ
         Bctg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1729824509; x=1730429309; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=Bhuf5SWebCkF1uVsLexTRTrl1uUVh0OSNA6SyDUwTAs=;
        b=V9UMYdXj8y402CFB2E1227cEdjbyCQL4kUfDI9csFdTDZCLzRiVuvLqGeZn55DsA4t
         MJHtyUo30C0nplsPWpJvsc9w/efMZY81nwf2NdWUOVcZpjBLf47pkapwuvkcWW9+QjcF
         utO6ANIeqEEnVe9vfZN0uq0i8uSIA6ch4oPEgzSti9aJsT05WPHA/koWfIwSuLFaAe/8
         5cKBBispJlF0uXlOX0TyFXxGIszus148tazatCkVHJ5xrNsyTMgaaIMdGVznHFbaSBXU
         tMusLufik7qC95R1BS4GWSpMKUeM79zn/IEE3pgaBXBbjdbzae3xWgv308LzJ8/n1OeE
         CkkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729824509; x=1730429309;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Bhuf5SWebCkF1uVsLexTRTrl1uUVh0OSNA6SyDUwTAs=;
        b=bsFPOAyGbUCYRMa+wWUAMN68rk03h93JJQ1OuH8InGwg0hX3akrvFmNzCsseKPxcrm
         VZK0vxWIK+cm31vU6nEQt7X8/dnn+mc/iTA1wzsoI2XUw7rZ3UkQ41YjclwYFVk/lZZW
         kYcVoWGeJQsE4XKb4Pj4nuJbEnUurvsDSqrIEHHeSWpLZ0USLo+Y7LO8PNLTRHaK7YPt
         IRJ17ypLZtpDIHTEm9hMpcas6m7I6FXlBcfKZjpUh2f8hCtwfII+XNSLOi/SbqpaR3dY
         8wpoIHWNIBP3dIP89ZvDiD5FLUf4LJXZpyCgHZ0Y/Pg4rHNmrr1MBFzlbwhoXDavFLMf
         hpqw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVhJyKPQklzba11DXUPHO2vW9UEz+khmaoPp1QSIH52TQyt9CR/WMPzFxBck/G6NZ+EvKSf6g==@lfdr.de
X-Gm-Message-State: AOJu0Yw0Q+UkbK2hdkDndeUyCcmouMkpyKwE3UwxFypWUjQ9unRC6qHT
	zhmSdSTmww/Ak7iP8eb20gz0Lr7ace4UJV6e0K674T6LR7pHG7uW
X-Google-Smtp-Source: AGHT+IHwSqHA5+oNSWES/cX5z52mdPs+Vwlk1qK0i1g8A02Ry+bZWYvCSY5L2BkbastsJgBEg/cT7Q==
X-Received: by 2002:a05:6e02:1d90:b0:3a0:933d:d306 with SMTP id e9e14a558f8ab-3a4d5975ddemr89683105ab.9.1729824508709;
        Thu, 24 Oct 2024 19:48:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c244:0:b0:3a1:a3bd:adc1 with SMTP id e9e14a558f8ab-3a4dc815ea7ls8064655ab.2.-pod-prod-01-us;
 Thu, 24 Oct 2024 19:48:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUuthXENRCXNAB8lUVYvUGvEwJ7bpbZ0EPcu1rNx55M/Bmx1laX+1zdXmBF8wlgzgMkYONdcC4rnTw=@googlegroups.com
X-Received: by 2002:a05:6602:14c9:b0:82c:ddfc:c57b with SMTP id ca18e2360f4ac-83af616e51fmr1105443539f.5.1729824507944;
        Thu, 24 Oct 2024 19:48:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729824507; cv=none;
        d=google.com; s=arc-20240605;
        b=PywQ3aSRmUtbKam6tedwSyC/hCq+d006wOVlCD14HVNifcrRuz5wJdHTbWO/HWrA4a
         l+UzPvb3n1T2IIGyenUIg0ApisWIzDtwq+Hi93MyPESMv76e6gZoI0LcL8drGdkH5ID1
         XycaV9cWIdFrNB7iUUNbI02HCru+IFtQrW2ucJNlqlOHREOu9RXhjXRpw+6O45kcOFDj
         F0pdBnonYNQEtLdPwayrxbS3JX6x28V+mQso1at6ySB6r0QRXRjPMZq4EwLokVKoI7i4
         YpR8+bjFpVeT45b5ksbpfcvVQBFVv5pgkUhAnIDFOuq6Ggselm9lzAcKH3JqWbF30Owz
         abrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=IMlkAz1rGfXdC3YuTmyO/PA2KhdShJ1qEJ3uVonYBbY=;
        fh=LGfE3L7HnWAjT6dwvICrwJwGr7LltSUqPEXuYV11Ivk=;
        b=OvRAgKthzUY3UIGvWEYlRlCzo1bv3O5yYlADC3lnFC/bF0OOhOYcDvlI8WQ7hEE5+m
         xpgHe7E3kVxjeL4ifeLrGxDrynU+w+bJm8PNp4nzwMZkKpNCGO7qPl+crRYSd4E8yhm2
         C29xHWDpAYbd5+JW/VjX2irnHWfU6TmFKUaRTJ2fiYWn24tTlCdyKzL5HhpKZbx+BPU9
         S9vvkQnGMWwUMiz9wZFUO7ExCc8+n58JKtnnpN8aZqitYKHHN79K3bqZl5Udj1GXxS/y
         6TfNesQLnlmzSlw1RMHOXDQT1uaUUZEoQiwkwDOSiWDoprIyXvsOWhCTeje2JkAMQkl1
         dv+g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=fblJALRk;
       spf=pass (google.com: domain of niharchaithanya@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=niharchaithanya@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x431.google.com (mail-pf1-x431.google.com. [2607:f8b0:4864:20::431])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-83b137c9274si910639f.1.2024.10.24.19.48.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Oct 2024 19:48:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of niharchaithanya@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) client-ip=2607:f8b0:4864:20::431;
Received: by mail-pf1-x431.google.com with SMTP id d2e1a72fcca58-717839f9eb6so29853b3a.3
        for <kasan-dev@googlegroups.com>; Thu, 24 Oct 2024 19:48:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVgVHb8PQDrXBhYGW2SBquWhoGe05YRTaauvY4UnquAB2zyZR1sPAmct43ozPpwbcPLX307bi4ZkEU=@googlegroups.com
X-Received: by 2002:a05:6a00:2d1a:b0:71e:66ed:7bd4 with SMTP id d2e1a72fcca58-72030a5183bmr5084342b3a.1.1729824506922;
        Thu, 24 Oct 2024 19:48:26 -0700 (PDT)
Received: from [192.168.1.17] ([171.76.80.180])
        by smtp.gmail.com with ESMTPSA id 41be03b00d2f7-7edc8698e30sm97594a12.52.2024.10.24.19.48.24
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Oct 2024 19:48:26 -0700 (PDT)
Message-ID: <f26691b2-fe26-4e13-a34f-c4a2a995f25f@gmail.com>
Date: Fri, 25 Oct 2024 08:18:21 +0530
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2] kasan:report: filter out kasan related stack entries
To: Andrey Konovalov <andreyknvl@gmail.com>, elver@google.com
Cc: ryabinin.a.a@gmail.com, glider@google.com, dvyukov@google.com,
 skhan@linuxfoundation.org, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org
References: <20241021195714.50473-1-niharchaithanya@gmail.com>
 <CA+fCnZf7sX2-H_jRMcJhiYxYZ=5f5oQ7iO__pQnjEXDLUS+fkg@mail.gmail.com>
Content-Language: en-US
From: Nihar Chaithanya <niharchaithanya@gmail.com>
In-Reply-To: <CA+fCnZf7sX2-H_jRMcJhiYxYZ=5f5oQ7iO__pQnjEXDLUS+fkg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: niharchaithanya@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=fblJALRk;       spf=pass
 (google.com: domain of niharchaithanya@gmail.com designates
 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=niharchaithanya@gmail.com;
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


On 23/10/24 19:30, Andrey Konovalov wrote:
> On Mon, Oct 21, 2024 at 9:58=E2=80=AFPM Nihar Chaithanya
> <niharchaithanya@gmail.com> wrote:
> Let's change the patch name prefix to "kasan: report:" (i.e. add an
> extra space between "kasan:" and "report:").
>
>> The reports of KASAN include KASAN related stack frames which are not
>> the point of interest in the stack-trace. KCSAN report filters out such
>> internal frames providing relevant stack trace. Currently, KASAN reports
>> are generated by dump_stack_lvl() which prints the entire stack.
>>
>> Add functionality to KASAN reports to save the stack entries and filter
>> out the kasan related stack frames in place of dump_stack_lvl() and
>> stack_depot_print().
>>
>> Within this new functionality:
>>          - A function kasan_dump_stack_lvl() in place of dump_stack_lvl(=
) is
>>            created which contains functionality for saving, filtering an=
d
>>            printing the stack-trace.
>>          - A function kasan_stack_depot_print() in place of
>>            stack_depot_print() is created which contains functionality f=
or
>>            filtering and printing the stack-trace.
>>          - The get_stack_skipnr() function is included to get the number=
 of
>>            stack entries to be skipped for filtering the stack-trace.
>>
>> Signed-off-by: Nihar Chaithanya <niharchaithanya@gmail.com>
>> Fixes: https://bugzilla.kernel.org/show_bug.cgi?id=3D215756
>> ---
>> Changes in v2:
>>          - Changed the function name from save_stack_lvl_kasan() to
>>            kasan_dump_stack_lvl().
>>          - Added filtering of stack frames for print_track() with
>>            kasan_stack_depot_print().
>>          - Removed redundant print_stack_trace(), and instead using
>>            stack_trace_print() directly.
>>          - Removed sanitize_stack_entries() and replace_stack_entry()
>>            functions.
>>          - Increased the buffer size in get_stack_skipnr to 128.
>>
>> Note:
>> When using sanitize_stack_entries() the output was innacurate for free a=
nd
>> alloc tracks, because of the missing ip value in print_track().
>> The buffer size in get_stack_skipnr() is increase as it was too small wh=
en
>> testing with some KASAN uaf bugs which included free and alloc tracks.
>>
>>   mm/kasan/report.c | 62 ++++++++++++++++++++++++++++++++++++++++++-----
>>   1 file changed, 56 insertions(+), 6 deletions(-)
>>
>> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
>> index b48c768acc84..e00cf764693c 100644
>> --- a/mm/kasan/report.c
>> +++ b/mm/kasan/report.c
>> @@ -261,6 +261,59 @@ static void print_error_description(struct kasan_re=
port_info *info)
>>                          info->access_addr, current->comm, task_pid_nr(c=
urrent));
>>   }
>>
>> +/* Helper to skip KASAN-related functions in stack-trace. */
>> +static int get_stack_skipnr(const unsigned long stack_entries[], int nu=
m_entries)
>> +{
>> +       char buf[128];
>> +       int len, skip;
>> +
>> +       for (skip =3D 0; skip < num_entries; ++skip) {
>> +               len =3D scnprintf(buf, sizeof(buf), "%ps", (void *)stack=
_entries[skip]);
>> +
>> +               /* Never show  kasan_* functions. */
>> +               if (strnstr(buf, "kasan_", len) =3D=3D buf)
>> +                       continue;
> Also check for "__kasan_" prefix: Right now, for the very first KASAN
> test, we get this alloc stack trace:
>
> [    1.799579] Allocated by task 63:
> [    1.799935]  __kasan_kmalloc+0x8b/0x90
> [    1.800353]  kmalloc_oob_right+0x95/0x6c0
> [    1.800801]  kunit_try_run_case+0x16e/0x280
> [    1.801267]  kunit_generic_run_threadfn_adapter+0x77/0xe0
> [    1.801863]  kthread+0x296/0x350
> [    1.802224]  ret_from_fork+0x2b/0x70
> [    1.802652]  ret_from_fork_asm+0x1a/0x30
>
> The __kasan_kmalloc frame is a part of KASAN internals and we want to
> skip that. kmalloc_oob_right is the function where the allocation
> happened, and that should be the first stack trace frame.
>
> (I suspect we'll have to adapt more of these from KFENCE, but let's do
> that after resolving the other issues.)
>
>> +               /*
>> +                * No match for runtime functions -- @skip entries to sk=
ip to
>> +                * get to first frame of interest.
>> +                */
>> +               break;
>> +       }
>> +
>> +       return skip;
>> +}
>> +
>> +/*
>> + * Use in place of stack_dump_lvl to filter KASAN related functions in
>> + * stack_trace.
> "Use in place of dump_stack() to filter out KASAN-related frames in
> the stack trace."
>
>> + */
>> +static void kasan_dump_stack_lvl(void)
> No need for the "_lvl" suffix - you removed the lvl argument.
>
>> +{
>> +       unsigned long stack_entries[KASAN_STACK_DEPTH] =3D { 0 };
>> +       int num_stack_entries =3D stack_trace_save(stack_entries, KASAN_=
STACK_DEPTH, 1);
>> +       int skipnr =3D get_stack_skipnr(stack_entries, num_stack_entries=
);
> For printing the access stack trace, we still want to keep the
> ip-based skipping (done via sanitize_stack_entries() in v1) - it's
> more precise than pattern-based matching in get_stack_skipnr(). But
> for alloc/free stack traces, we can only use get_stack_skipnr().
>
> However, I realized I don't fully get the point of replacing a stack
> trace entry when doind the ip-based skipping. Marco, is this something
> KCSAN-specific? I see that this is used for reodered_to thing.
When I included ip-based skipping for filtering access stack trace the=20
output was
inconsistent where the Freed track was not fully printed and it also=20
triggered
the following warning a few times:

[=C2=A0=C2=A0=C2=A0 6.467470][ T4653] Freed by task 511183648:
[=C2=A0=C2=A0=C2=A0 6.467792][ T4653] ------------[ cut here ]------------
[=C2=A0=C2=A0=C2=A0 6.468194][ T4653] pool index 100479 out of bounds (466)=
 for stack=20
id ffff8880
[=C2=A0=C2=A0=C2=A0 6.468862][ T4653] WARNING: CPU: 1 PID: 4653 at lib/stac=
kdepot.c:452=20
depot_fetch_stack+0x86/0xb0

This was not present when using pattern based skipping. Does modifying=20
access
stack trace when using sanitize_stack_entries() modify the free and=20
alloc tracks
as well? In that case shall we just use pattern based skipping.
>> +
>> +       dump_stack_print_info(KERN_ERR);
>> +       stack_trace_print(stack_entries + skipnr, num_stack_entries - sk=
ipnr, 0);
>> +       pr_err("\n");
>> +}
>> +
>> +/*
>> + * Use in place of stack_depot_print to filter KASAN related functions =
in
>> + * stack_trace.
> "Use in place of stack_depot_print() to filter out KASAN-related
> frames in the stack trace."
>
>> + */
>> +static void kasan_stack_depot_print(depot_stack_handle_t stack)
>> +{
>> +       unsigned long *entries;
>> +       unsigned int nr_entries;
>> +
>> +       nr_entries =3D stack_depot_fetch(stack, &entries);
>> +       int skipnr =3D get_stack_skipnr(entries, nr_entries);
>> +
>> +       if (nr_entries > 0)
>> +               stack_trace_print(entries + skipnr, nr_entries - skipnr,=
 0);
>> +}
>> +
>>   static void print_track(struct kasan_track *track, const char *prefix)
>>   {
>>   #ifdef CONFIG_KASAN_EXTRA_INFO
>> @@ -277,7 +330,7 @@ static void print_track(struct kasan_track *track, c=
onst char *prefix)
>>          pr_err("%s by task %u:\n", prefix, track->pid);
>>   #endif /* CONFIG_KASAN_EXTRA_INFO */
>>          if (track->stack)
>> -               stack_depot_print(track->stack);
>> +               kasan_stack_depot_print(track->stack);
>>          else
>>                  pr_err("(stack is not available)\n");
>>   }
>> @@ -374,9 +427,6 @@ static void print_address_description(void *addr, u8=
 tag,
>>   {
>>          struct page *page =3D addr_to_page(addr);
>>
>> -       dump_stack_lvl(KERN_ERR);
>> -       pr_err("\n");
> This new line we want to keep.
>
>> -
>>          if (info->cache && info->object) {
>>                  describe_object(addr, info);
>>                  pr_err("\n");
>> @@ -484,11 +534,11 @@ static void print_report(struct kasan_report_info =
*info)
>>                  kasan_print_tags(tag, info->first_bad_addr);
>>          pr_err("\n");
>>
>> +       kasan_dump_stack_lvl();
>> +
>>          if (addr_has_metadata(addr)) {
>>                  print_address_description(addr, tag, info);
>>                  print_memory_metadata(info->first_bad_addr);
>> -       } else {
>> -               dump_stack_lvl(KERN_ERR);
>>          }
>>   }
>>
>> --
>> 2.34.1
>>
> Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/f=
26691b2-fe26-4e13-a34f-c4a2a995f25f%40gmail.com.
