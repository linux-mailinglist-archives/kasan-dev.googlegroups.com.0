Return-Path: <kasan-dev+bncBDW2JDUY5AORBT4JVKZAMGQE6IG6JOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id DDE8B8C9757
	for <lists+kasan-dev@lfdr.de>; Mon, 20 May 2024 01:01:36 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-523b4b04fa2sf3709523e87.1
        for <lists+kasan-dev@lfdr.de>; Sun, 19 May 2024 16:01:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1716159696; cv=pass;
        d=google.com; s=arc-20160816;
        b=MovWSgksZDQtgCaf3CPT02yTzrtpJ0YDJz6cPthtyIZ8Ohz0lVnfRmAXMGgsl7lJDl
         HjY30/5HxEhqTlv6mHXf8mhVAMCXOC9EXRyMxUgZaO2V0jIuAPlvGspXqLFwpgtPaL8c
         6KbaYlkbdZ5MrY5yO38eLFB1bNBTTbOmaM7qtQhNt9A9GguermUQaOAXrG4iuANP/H5O
         IUaSmq4uZoIKJgfxaUlNj2vdNEWc2AZXw5vSywdE7MVQh3dFVhzP8cQ0d5UV/TkO2juH
         ickEcV+Vc3soPq26ub2Rg2js7jyk3/XjmXVE50Gds8g73XsRbMpY+1ZOBt7oFLB+Hr0B
         eufA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=zpKvP4ZE1+A6dWV8iT81u3LAXpCzHq2EGSjgXkOMoug=;
        fh=dgkTYj2/3Jo35/e8MzLuIw/otyEFGxqKiAJDgBERMl0=;
        b=clmQaeYstCxQwkV+1YIwdca9EHvmbBFH+/uoMOK/D0EuSPNuiopXx5eIHZCYn/3HBj
         uSeqmBRyJc3lwPRYUOpw5hoyPexTARGZgUHQtPJG1NG3v1JmlrHEH0iwfgc3MSzE2Rh1
         z1L925Lq7DwOiAAbUjaLP2yWgDTOY9mm2zDGR4LytX0F14X50MGQkFesMULE9nk/dC9K
         D7FQyceBfzi1br27lVJIJ/HAUrVRWt3Lfo6fnLhPv1AyOMLj/9ljkOXJkleXJAppxI8N
         jCyIBbed+MdHFHgHNX6BqSX5gfswhwJ15Y6CgAfSmdM6G40Stj8Yg9n9HDTsN5OQNk/p
         1GlQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QDHc5y0O;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1716159696; x=1716764496; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=zpKvP4ZE1+A6dWV8iT81u3LAXpCzHq2EGSjgXkOMoug=;
        b=fj6ktm1THoblZMIgJVBCRX0eHZvv4qpbsIy8yQkrVASMG/i8bnQkFGTClPfVvQBsEV
         VbE6VKxgocN1vl1a6fQclUPs44nTbHbapozy/LcJdKOhxSTVsU4xIUJRKq3mRWLZWEkM
         fjaYw8skncPhtcNpl5Oc1EYYolGEZ2z1wGrhA6NOEoAa97/vIK8QdwAiX7ts0Jw5lUm2
         lFpYovAGRfbuH7Jli0GddaO6GK3Maq/OcO7/vW9aHY+PLR19hMIJqlBAyPPxIj0+w6BM
         Uw8KIYbfS1+WuXZeIGOO+g5CJUc3ZzsmiAWTS7GPx2nK0M492t5bG4ZvXTg8W5YY25Hs
         S0dA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1716159696; x=1716764496; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zpKvP4ZE1+A6dWV8iT81u3LAXpCzHq2EGSjgXkOMoug=;
        b=OljTn3p8amY2Phx7zKzBagrqV4vOGWpTMk+atpGoZhZqb3vkhNsmGsFrZ2mUpwuInk
         35Fu2RZGg3xYici668Upo4CixwKYW5R89yuP76wO/AsHZGbNLsnJRj+aIc+rA3YJW/qV
         X9k1JPAyMK3DJ1ZNFRH3dFO2at8OnRX5y8rKVJoRmCm+4TdVH6AmdAVPHqA/qIB5/Xr0
         2QbM8TRgKy9KzZ3vmVxwz//vJZEXnzh+8rQ14gNpMH+0vy+XSlB8OJZt7b2+L56fLSgp
         1dvq45BDFHxdl6Md/R42JoWtJXl5QM5fKeAZg5Vs4gUPoW3+4O5FkWpHYNvzz2ROyBej
         1mAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1716159696; x=1716764496;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=zpKvP4ZE1+A6dWV8iT81u3LAXpCzHq2EGSjgXkOMoug=;
        b=R/glClB6G19KzllXAnN7iAOFV2HTvGH7CuR+ObsB9MkPPDPR/Gqit/0O5GJNsLUQ20
         XvQmfmohsc3K87tIAsJkL3D+eqkXNp0BmaR+8xT/UkoR76ZwRP46lxppBy1PGQCebai4
         ytC3Iyq8gGY65gWZTN6QahPTm9E0L3UmtcHi27WXmUBeBBku7Okk8cuJ7auj/6DqE3mP
         5/MafVPupBjShqJsJyJYUfykWrzthHderd93YB9h0YMo2r5waYLSwBiybkIqDaEavHo1
         AganoqJRJXvUe+2aB8DVuiD7QehXCJldADwMDHZL22u1d6FYVHKaeQcVgWsQYN8Wc+oD
         rDSQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWUbmr0JO8fSff+vy34gjqgVYLAErH+TvYoNd3Tpl3QFjSSP25uGMayulc/ZVR/6RJMikou57w/u126LvD0fukZYaqgIMeVeA==
X-Gm-Message-State: AOJu0YxorGZ/UbwudiL3Up/MfznpxXcNT98syosN1ZLw8elgLM3x5ZCm
	/NtZZnBSNwnPGk6pPjO/khSqvHHmp5sg4enRoFyvOe6Z0XSf1uLw
X-Google-Smtp-Source: AGHT+IHJkCqvi7HLNMUVZAfJ4aVvyM35HnY5JgQ/H+L7tafr5vicUrX4fIKvDdzwmjW1evbLDYZekQ==
X-Received: by 2002:a2e:96d2:0:b0:2e1:c448:d61e with SMTP id 38308e7fff4ca-2e51fd4530dmr237204631fa.15.1716159695781;
        Sun, 19 May 2024 16:01:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9ac3:0:b0:2e3:7cf4:8cfd with SMTP id 38308e7fff4ca-2e4b57217c5ls24937901fa.0.-pod-prod-05-eu;
 Sun, 19 May 2024 16:01:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWtWYaQGihJsd25S1OEf4JR8wyGmToQjCgCuvjVNbG1kv0BHF7+Gj3UR5KKCloDgyxfCVZ1XoG+eDgxJsFIGHL/4WQrWHT9rxZgfw==
X-Received: by 2002:a05:6512:3f20:b0:51d:4383:9e59 with SMTP id 2adb3069b0e04-5220f86c902mr21485748e87.0.1716159693701;
        Sun, 19 May 2024 16:01:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1716159693; cv=none;
        d=google.com; s=arc-20160816;
        b=Xayb1hUTcIo9De1pCt5y3vM/BvKSPiwgo+qLnvypDrGh6T1mfeOFVu67kn8Cru5v10
         rHBYPRHYEzKdQRhjLVx8eFCzWYsgCB3YCbNICZyL2aD4vmlgFEV9SpdzlyJGzQOuyhXq
         GLdQxQ1cLqGwMTDfMnZ0nDnUkjlOam+E1ogMSjquRo8pOSOoCAsJBInqv3MDWdFQ4DJc
         JZoV5oY7xK1jZ3N4iVs+vRHSio0T9si34po/wYshZkDz1sl12GMw1RqY47hhxHjntMb2
         Pdr/A7uThp71Iy0G7N4Ns2ORFiIfGlmM91K15Q7fVObiKJCfjApjIue5uH6vI1MwuXLD
         eyew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=pP8H1QGY/sk27w7vno3j6ucygejbv8hF4gXfEvTkZuE=;
        fh=3Vjlnr/p61WCGtkAw2BGlOrSc3PaLLPZY8kXGrB1ZNo=;
        b=LR1Jeyk4B5listq0xv443J+El5GkwD5x52dA2KJRdErVMB786+3XiiYkJxJGABlBdQ
         2rvaHWZFwuYf9THAdtV0WfQo8V6jgNzbY7jMDqQp4hloXAAwZDmuFLq37jHyu8hfSRi3
         TBy8qg/XTti9Cxot/jLZagEtUyekmUoI4HdVFawt0WfBfqwjIAXBl4kRwRBrX1b4ML5D
         9wxo9TRPy9PPkcWC9xjadSPWX/x0VOGefUbpPbJzpd2xd4JTGbQQ7MeQfHfwtDECk/DQ
         ZMsa14l+djoXpUyQrva1SPTKhBHtT6ERlccSVw5OqvHjZK928YuftLk6Pa18cuC6fnsK
         aW/w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QDHc5y0O;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x42d.google.com (mail-wr1-x42d.google.com. [2a00:1450:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-521f38daea4si561225e87.13.2024.05.19.16.01.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 19 May 2024 16:01:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) client-ip=2a00:1450:4864:20::42d;
Received: by mail-wr1-x42d.google.com with SMTP id ffacd0b85a97d-34db9a38755so1986031f8f.1
        for <kasan-dev@googlegroups.com>; Sun, 19 May 2024 16:01:33 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWyCljmTbXgsL8ISQ2nYHBjhIqiNfDTGAJI1Szqx6cUzpDJwSCpZ7rXK0cFSibYtwkdhW0Srzj9GqJBTN5TP14snJ8vdUoiEQA0sA==
X-Received: by 2002:a05:6000:c0a:b0:34d:a33d:7f3e with SMTP id
 ffacd0b85a97d-3504aa634c2mr23316871f8f.65.1716159692654; Sun, 19 May 2024
 16:01:32 -0700 (PDT)
MIME-Version: 1.0
References: <20240427205020.3ecf3895@yea> <20240501144156.17e65021@outsider.home>
 <CA+fCnZdNBEekgcfaGafJKmpb-A7R6rBuL5QojOhpqkHZvz1nKg@mail.gmail.com> <20240518170548.13124cfa@yea>
In-Reply-To: <20240518170548.13124cfa@yea>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 20 May 2024 01:01:21 +0200
Message-ID: <CA+fCnZeeJub5iCwwwGM2pDt9wzX=T4+wpZbbGhKQ7Qbtb+tFeA@mail.gmail.com>
Subject: Re: Machine freezes after running KASAN KUnit test 21 with a GCC 13.2
 built kernel but runs tests fine with a CLANG 18 build kernel (v6.9-rc5,
 32bit ppc, PowerMac G4 DP)
To: Erhard Furtner <erhard_f@mailbox.org>
Cc: Nico Pache <npache@redhat.com>, kasan-dev@googlegroups.com, 
	linuxppc-dev@lists.ozlabs.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=QDHc5y0O;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Sat, May 18, 2024 at 5:05=E2=80=AFPM Erhard Furtner <erhard_f@mailbox.or=
g> wrote:
>
> The patch fixes the issue on ppc too. Thanks!

You're welcome!

> The test run continues and I get a failing one later on (though not '31 r=
cu_uaf' Nico reported but) '65 vmalloc_oob':
> [...]
> BUG: KASAN: vmalloc-out-of-bounds in vmalloc_oob+0x1d0/0x3cc
> Read of size 1 at addr f10457f3 by task kunit_try_catch/190
>
> CPU: 0 PID: 190 Comm: kunit_try_catch Tainted: G    B            N 6.9.1-=
PMacG4-dirty #1
> Hardware name: PowerMac3,1 7450 0x80000201 PowerMac
> Call Trace:
> [f197bd60] [c15f48ac] dump_stack_lvl+0x80/0xac (unreliable)
> [f197bd80] [c04c3f14] print_report+0xd4/0x4fc
> [f197bdd0] [c04c456c] kasan_report+0xf8/0x10c
> [f197be50] [c04c723c] vmalloc_oob+0x1d0/0x3cc
> [f197bed0] [c0c29e98] kunit_try_run_case+0x3bc/0x5d8
> [f197bfa0] [c0c2f1c8] kunit_generic_run_threadfn_adapter+0xa4/0xf8
> [f197bfc0] [c00facf8] kthread+0x384/0x394
> [f197bff0] [c002e304] start_kernel_thread+0x10/0x14
>
> The buggy address belongs to the virtual mapping at
>  [f1045000, f1047000) created by:
>  vmalloc_oob+0x70/0x3cc
>
> The buggy address belongs to the physical page:
> page: refcount:1 mapcount:0 mapping:00000000 index:0x0 pfn:0x79f8b
> flags: 0x80000000(zone=3D2)
> page_type: 0xffffffff()
> raw: 80000000 00000000 00000122 00000000 00000000 00000000 ffffffff 00000=
001
> raw: 00000000
> page dumped because: kasan: bad access detected
>
> Memory state around the buggy address:
>  f1045680: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
>  f1045700: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
> >f1045780: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 03 f8
>                                                      ^
>  f1045800: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
>  f1045880: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> BUG: KASAN: vmalloc-out-of-bounds in vmalloc_oob+0x294/0x3cc
> Read of size 1 at addr f10457f8 by task kunit_try_catch/190
>
> CPU: 0 PID: 190 Comm: kunit_try_catch Tainted: G    B            N 6.9.1-=
PMacG4-dirty #1
> Hardware name: PowerMac3,1 7450 0x80000201 PowerMac
> Call Trace:
> [f197bd60] [c15f48ac] dump_stack_lvl+0x80/0xac (unreliable)
> [f197bd80] [c04c3f14] print_report+0xd4/0x4fc
> [f197bdd0] [c04c456c] kasan_report+0xf8/0x10c
> [f197be50] [c04c7300] vmalloc_oob+0x294/0x3cc
> [f197bed0] [c0c29e98] kunit_try_run_case+0x3bc/0x5d8
> [f197bfa0] [c0c2f1c8] kunit_generic_run_threadfn_adapter+0xa4/0xf8
> [f197bfc0] [c00facf8] kthread+0x384/0x394
> [f197bff0] [c002e304] start_kernel_thread+0x10/0x14
>
> The buggy address belongs to the virtual mapping at
>  [f1045000, f1047000) created by:
>  vmalloc_oob+0x70/0x3cc
>
> The buggy address belongs to the physical page:
> page: refcount:1 mapcount:0 mapping:00000000 index:0x0 pfn:0x79f8b
> flags: 0x80000000(zone=3D2)
> page_type: 0xffffffff()
> raw: 80000000 00000000 00000122 00000000 00000000 00000000 ffffffff 00000=
001
> raw: 00000000
> page dumped because: kasan: bad access detected
>
> Memory state around the buggy address:
>  f1045680: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
>  f1045700: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
> >f1045780: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 03 f8
>                                                         ^
>  f1045800: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
>  f1045880: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>     # vmalloc_oob: ASSERTION FAILED at mm/kasan/kasan_test.c:1680
>     Expected p_ptr is not null, but is
>     not ok 65 vmalloc_oob
> [...]
>
> This is in line with my CLANG 18 build where I get the same vmalloc_oob f=
ailure: https://github.com/ClangBuiltLinux/linux/issues/2020.
>
> There Nathan already found out this happens when the machine got more tha=
n 867 MB of RAM. Probably this test failing may be a ppc specific issue. I =
can also open a new thread for that if you'd like.

Yeah, I suspect this is something ppc-specific and might not even be
KASAN-related: somehow vmalloc_to_page + page_address return NULL. A
separate thread with ppc maintainers makes sense.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZeeJub5iCwwwGM2pDt9wzX%3DT4%2BwpZbbGhKQ7Qbtb%2BtFeA%40mai=
l.gmail.com.
