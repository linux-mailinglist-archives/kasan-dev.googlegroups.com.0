Return-Path: <kasan-dev+bncBD7I3CGX5IPRBUUFZL6AKGQE5JOOQ4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63c.google.com (mail-ej1-x63c.google.com [IPv6:2a00:1450:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F544296A1D
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Oct 2020 09:14:26 +0200 (CEST)
Received: by mail-ej1-x63c.google.com with SMTP id c11sf254760ejp.9
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Oct 2020 00:14:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603437266; cv=pass;
        d=google.com; s=arc-20160816;
        b=yB0MLj8cwlLkX5BS2p0e6Y8FMuutpwBdqlBJjqa0S4XR5bHA8Ap3IaW52MsXqrQ3dF
         FpKoraLC4pXQEo2ljeMPFDVmod6c3/hKB6ISvsYyIAJGlCzUF8H3Mb9uJ/T3Dola4jGz
         S7IkGBZEjgd3Wv1m+EjOHZlByP5I6vmoIJmsgm9Ll2bpdPvVorIRiZq8IqPP9vBNePdG
         SLVSnEYH+st5CErYRDwEagrQMI/L3M+sTOsnldlP1u0OFFwiApqhu8CdGZBRbrf9gku+
         ipizSGc2S2dFqyEshLP9Zv6a3uIbrUetoQV67TqOgTTtbtCalUC/1YLncH1gk2vV66AU
         Veyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=ioI4nnuQkX9hsNjr1P93SSgWkxp3ozxmmiJUEl5kdrw=;
        b=XBoRd9rq5DFNoifN0aHnXLFuzYEWM0ipsGpplz/lxad8JvhCYo4padMb6Ki81vBofe
         5Um57TLIeeC5klOJ6n3MUJ24Z9c4dJv4z3nfWaz6SZ+WEvnkb64vt1omexyOuHB9GOu7
         305p4G49OyFIf3SD4nE+Wzyr+l4wNog4V+XOdwzlbKWFv4cQd/VLCUekfLfXeKoKAENE
         9lUl3wxmcJYdpYc6oDFr8vD9QhzxP4RuDvIKntV01FzTeinxHrpzO2PNIRx+r/Z1eThv
         4czxuwud5AGfiC0eAte4X4A5uQy2KArk66CVm1A41NrwRfSYz4Xv9D5woMGPd3Mzf/sR
         QlyA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rasmusvillemoes.dk header.s=google header.b=fIw2nnxw;
       spf=pass (google.com: domain of linux@rasmusvillemoes.dk designates 2a00:1450:4864:20::643 as permitted sender) smtp.mailfrom=linux@rasmusvillemoes.dk
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ioI4nnuQkX9hsNjr1P93SSgWkxp3ozxmmiJUEl5kdrw=;
        b=oVaGyRgPR+EbvnchAVAH5wKeWRLeU4UWHCS1A/955HIBfcHFmCqGbRxr+CNkWez+2h
         SDo9JSPqcuwFJpDZnEQliwY3AKId7bdYK4U3DCYT6EhM5W/CZP+jaVeuUlXai+TGSBkj
         OYhVEVUTJUjTeqOPDFoPUQp8/CdcKc5B+c1Xk4WC0JnaR0ZYwteInIW+1PEF9RD+k7XA
         QBDR82jrhY0w+uxtRhcWcVY4mDkfVpOtLBdHMsEZRGVC+XLATyUvZQ8ldNseMDlQVGgh
         uayHKkaWmRc6GEBA3tTGBDIJ9f+BUQ/09bwjNbRiY8hZptTgCvFbxfdpwA3YVMfEAoq2
         ij7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ioI4nnuQkX9hsNjr1P93SSgWkxp3ozxmmiJUEl5kdrw=;
        b=VHowqtFN7bXQ0I+SCXtU+4tK2uv1ABAoOl9/wL3U+kgm2+fCofm00BFy7hZLk9m9Jd
         bvRE6vJdHgU9KiVVKuwmZfXW39wSiYbx0rkoQUDSykqTUe9wCE3pv47A5m3hBXdM8HWT
         LFvowk2C6w52vNS4gXjquiXjOMoBf0XTD3FDbQWtFsXNmRl2lcy5v3LjUnB2d6aW59S2
         uBHvsROFqFtzDSbRoEqpwPBBbjDSB6XmM7dQmYXRRnmcNopno82oycGCv6NfCEpp8Ndg
         YjGmsrW2jRT3M5zzSs40ZLGlaX5SGWvxnACXk9FPVV5rAyezNH3lXrXIFClifExoqofT
         FjEw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533aWbCSj/w1d590ND+X6sHPjTZO3mz4vnmeKavlFWCunxyAee81
	2VqqU5ax6m4yIPNoC69hDfo=
X-Google-Smtp-Source: ABdhPJy6tsIMZG3Ub6hKC+340tSvwpxHoYR0d3gQ9dLPPtVhqXyfOHCuaNvDuAnnfP3A6yBQEAsUQQ==
X-Received: by 2002:a17:906:33ca:: with SMTP id w10mr678503eja.195.1603437266249;
        Fri, 23 Oct 2020 00:14:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:1d3c:: with SMTP id dh28ls657591edb.0.gmail; Fri,
 23 Oct 2020 00:14:24 -0700 (PDT)
X-Received: by 2002:a50:fb0d:: with SMTP id d13mr904276edq.85.1603437264677;
        Fri, 23 Oct 2020 00:14:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603437264; cv=none;
        d=google.com; s=arc-20160816;
        b=kstfEctPNdPonS606T94fMzoRfcQ/Gka8eeitSCm2MUYhSgbZ10VSubTYkbKSH+16j
         vGpPI7yiZbqAPccfjBpmF8ptNuSN1kfAxUAw2J8egO3UmVtuk5nxwEUzaC+AlQ5lgchC
         rFR89kwyPECarPrnVl+nMBKS43w962I6i2gqEZVa5F/IT+8gC1JN2P7xeOHdYnd/SQ9U
         /3UkPxnd0W4NPK4ur/E9jV8LPpPVK7jXkES7bq/25QXp1NPgZ6z5lca9rVdHTnzrGqPJ
         6GrL55q8g4xY7Clnk3fEX6MX1vbuqbm5KEx6ZEFOCrOdlTS0GS9EPKRot80hjC5z4iAt
         atcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=tV2JdgeetWkMo3b0CNfPI5PIf7h/qWNZxkMeAZIAXgY=;
        b=PXSwtXAKjnDDvrkkoI+WjVJd3Ozcm0ahkuuKm2NnjGCUjGnqzGneH+brf6rS60S3o3
         6rlVYdkeZmOCJuaPz10xI8P4nfqoo0ye0ugrCZAXU91ZjK/e0iJx2U1pOyjSFB7mGOjq
         A6tR6e9egflpXuLca+zCBqvGocMnXp4A464bC11mJYDwJD01zKjujAwfeYIM19rRXh2q
         NkGnEMEIiCfgBZJ25FMNfdC8vwydDwYLix3HfiOVw58j/yMBz+uyNABnPlGrmpC4OcBO
         aFlRCzWJyANUSLHpHjHJblP02KqRDmIUT69wT8d0rn7Rc+YtOjZXT4bEpN1cj2X8fEcQ
         MeGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rasmusvillemoes.dk header.s=google header.b=fIw2nnxw;
       spf=pass (google.com: domain of linux@rasmusvillemoes.dk designates 2a00:1450:4864:20::643 as permitted sender) smtp.mailfrom=linux@rasmusvillemoes.dk
Received: from mail-ej1-x643.google.com (mail-ej1-x643.google.com. [2a00:1450:4864:20::643])
        by gmr-mx.google.com with ESMTPS id u2si25153edp.5.2020.10.23.00.14.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 23 Oct 2020 00:14:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of linux@rasmusvillemoes.dk designates 2a00:1450:4864:20::643 as permitted sender) client-ip=2a00:1450:4864:20::643;
Received: by mail-ej1-x643.google.com with SMTP id qh17so942619ejb.6
        for <kasan-dev@googlegroups.com>; Fri, 23 Oct 2020 00:14:24 -0700 (PDT)
X-Received: by 2002:a17:906:a1d4:: with SMTP id bx20mr664255ejb.262.1603437264294;
        Fri, 23 Oct 2020 00:14:24 -0700 (PDT)
Received: from [172.16.11.132] ([81.216.59.226])
        by smtp.gmail.com with ESMTPSA id h17sm287717ejf.98.2020.10.23.00.14.22
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 23 Oct 2020 00:14:23 -0700 (PDT)
Subject: Re: [LTP] mmstress[1309]: segfault at 7f3d71a36ee8 ip
 00007f3d77132bdf sp 00007f3d71a36ee8 error 4 in
 libc-2.27.so[7f3d77058000+1aa000]
To: Sean Christopherson <sean.j.christopherson@intel.com>,
 Linus Torvalds <torvalds@linux-foundation.org>
Cc: =?UTF-8?Q?Daniel_D=c3=adaz?= <daniel.diaz@linaro.org>,
 Naresh Kamboju <naresh.kamboju@linaro.org>,
 Stephen Rothwell <sfr@canb.auug.org.au>,
 "Matthew Wilcox (Oracle)" <willy@infradead.org>, zenglg.jy@cn.fujitsu.com,
 "Peter Zijlstra (Intel)" <peterz@infradead.org>,
 Viresh Kumar <viresh.kumar@linaro.org>, X86 ML <x86@kernel.org>,
 open list <linux-kernel@vger.kernel.org>, lkft-triage@lists.linaro.org,
 "Eric W. Biederman" <ebiederm@xmission.com>, linux-mm <linux-mm@kvack.org>,
 linux-m68k <linux-m68k@lists.linux-m68k.org>,
 Linux-Next Mailing List <linux-next@vger.kernel.org>,
 Thomas Gleixner <tglx@linutronix.de>, kasan-dev
 <kasan-dev@googlegroups.com>, Dmitry Vyukov <dvyukov@google.com>,
 Geert Uytterhoeven <geert@linux-m68k.org>,
 Christian Brauner <christian.brauner@ubuntu.com>,
 Ingo Molnar <mingo@redhat.com>, LTP List <ltp@lists.linux.it>,
 Al Viro <viro@zeniv.linux.org.uk>
References: <CA+G9fYvHze+hKROmiB0uL90S8h9ppO9S9Xe7RWwv808QwOd_Yw@mail.gmail.com>
 <CAHk-=wg5-P79Hr4iaC_disKR2P+7cRVqBA9Dsria9jdVwHo0+A@mail.gmail.com>
 <CA+G9fYv=DUanNfL2yza=y9kM7Y9bFpVv22Wd4L9NP28i0y7OzA@mail.gmail.com>
 <CA+G9fYudry0cXOuSfRTqHKkFKW-sMrA6Z9BdQFmtXsnzqaOgPg@mail.gmail.com>
 <CAHk-=who8WmkWuuOJeGKa-7QCtZHqp3PsOSJY0hadyywucPMcQ@mail.gmail.com>
 <CAHk-=wi=sf4WtmZXgGh=nAp4iQKftCKbdQqn56gjifxWNpnkxw@mail.gmail.com>
 <CAEUSe78A4fhsyF6+jWKVjd4isaUeuFWLiWqnhic87BF6cecN3w@mail.gmail.com>
 <CAHk-=wgqAp5B46SWzgBt6UkheVGFPs2rrE6H4aqLExXE1TXRfQ@mail.gmail.com>
 <20201023050214.GG23681@linux.intel.com>
From: Rasmus Villemoes <linux@rasmusvillemoes.dk>
Message-ID: <356811ab-cb08-7685-ca01-fe58b5654953@rasmusvillemoes.dk>
Date: Fri, 23 Oct 2020 09:14:21 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20201023050214.GG23681@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: linux@rasmusvillemoes.dk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rasmusvillemoes.dk header.s=google header.b=fIw2nnxw;
       spf=pass (google.com: domain of linux@rasmusvillemoes.dk designates
 2a00:1450:4864:20::643 as permitted sender) smtp.mailfrom=linux@rasmusvillemoes.dk
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

On 23/10/2020 07.02, Sean Christopherson wrote:
> On Thu, Oct 22, 2020 at 08:05:05PM -0700, Linus Torvalds wrote:
>> On Thu, Oct 22, 2020 at 6:36 PM Daniel D=C3=ADaz <daniel.diaz@linaro.org=
> wrote:
>>>
>>> The kernel Naresh originally referred to is here:
>>>   https://builds.tuxbuild.com/SCI7Xyjb7V2NbfQ2lbKBZw/
>>
>> Thanks.
>>
>> And when I started looking at it, I realized that my original idea
>> ("just look for __put_user_nocheck_X calls, there aren't so many of
>> those") was garbage, and that I was just being stupid.
>>
>> Yes, the commit that broke was about __put_user(), but in order to not
>> duplicate all the code, it re-used the regular put_user()
>> infrastructure, and so all the normal put_user() calls are potential
>> problem spots too if this is about the compiler interaction with KASAN
>> and the asm changes.
>>
>> So it's not just a couple of special cases to look at, it's all the
>> normal cases too.
>>
>> Ok, back to the drawing board, but I think reverting it is probably
>> the right thing to do if I can't think of something smart.
>>
>> That said, since you see this on x86-64, where the whole ugly trick with=
 that
>>
>>    register asm("%"_ASM_AX)
>>
>> is unnecessary (because the 8-byte case is still just a single
>> register, no %eax:%edx games needed), it would be interesting to hear
>> if the attached patch fixes it. That would confirm that the problem
>> really is due to some register allocation issue interaction (or,
>> alternatively, it would tell me that there's something else going on).
>=20
> I haven't reproduced the crash, but I did find a smoking gun that confirm=
s the
> "register shenanigans are evil shenanigans" theory.  I ran into a similar=
 thing
> recently where a seemingly innocuous line of code after loading a value i=
nto a
> register variable wreaked havoc because it clobbered the input register.
>=20
> This put_user() in schedule_tail():
>=20
>    if (current->set_child_tid)
>            put_user(task_pid_vnr(current), current->set_child_tid);
>=20
> generates the following assembly with KASAN out-of-line:
>=20
>    0xffffffff810dccc9 <+73>: xor    %edx,%edx
>    0xffffffff810dcccb <+75>: xor    %esi,%esi
>    0xffffffff810dcccd <+77>: mov    %rbp,%rdi
>    0xffffffff810dccd0 <+80>: callq  0xffffffff810bf5e0 <__task_pid_nr_ns>
>    0xffffffff810dccd5 <+85>: mov    %r12,%rdi
>    0xffffffff810dccd8 <+88>: callq  0xffffffff81388c60 <__asan_load8>
>    0xffffffff810dccdd <+93>: mov    0x590(%rbp),%rcx
>    0xffffffff810dcce4 <+100>: callq  0xffffffff817708a0 <__put_user_4>
>    0xffffffff810dcce9 <+105>: pop    %rbx
>    0xffffffff810dccea <+106>: pop    %rbp
>    0xffffffff810dcceb <+107>: pop    %r12
>=20
> __task_pid_nr_ns() returns the pid in %rax, which gets clobbered by
> __asan_load8()'s check on current for the current->set_child_tid derefere=
nce.
>=20

Yup, and you don't need KASAN to implicitly generate function calls for
you. With x86_64 defconfig, I get

extern u64 __user *get_destination(int x, int y);

void pu_test(void)
{
	u64 big =3D 0x1234abcd5678;

	if (put_user(big, get_destination(4, 5)))
		pr_warn("uh");
}

to generate

0000000000004d60 <pu_test>:
    4d60:       53                      push   %rbx
    4d61:       be 05 00 00 00          mov    $0x5,%esi
    4d66:       bf 04 00 00 00          mov    $0x4,%edi
    4d6b:       e8 00 00 00 00          callq  4d70 <pu_test+0x10>
                        4d6c: R_X86_64_PC32     get_destination-0x4
    4d70:       48 89 c1                mov    %rax,%rcx
    4d73:       e8 00 00 00 00          callq  4d78 <pu_test+0x18>
                        4d74: R_X86_64_PC32     __put_user_8-0x4
    4d78:       85 c9                   test   %ecx,%ecx
    4d7a:       75 02                   jne    4d7e <pu_test+0x1e>
    4d7c:       5b                      pop    %rbx
    4d7d:       c3                      retq
    4d7e:       5b                      pop    %rbx
    4d7f:       48 c7 c7 00 00 00 00    mov    $0x0,%rdi
                        4d82: R_X86_64_32S      .rodata.str1.1+0xfa
    4d86:       e9 00 00 00 00          jmpq   4d8b <pu_test+0x2b>
                        4d87: R_X86_64_PC32     printk-0x4


That's certainly garbage. Now, I don't know if it's a sufficient fix (or
could break something else), but the obvious first step of rearranging
so that the ptr argument is evaluated before the assignment to __val_pu

diff --git a/arch/x86/include/asm/uaccess.h b/arch/x86/include/asm/uaccess.=
h
index 477c503f2753..b5d3290fcd09 100644
--- a/arch/x86/include/asm/uaccess.h
+++ b/arch/x86/include/asm/uaccess.h
@@ -235,13 +235,13 @@ extern void __put_user_nocheck_8(void);
 #define do_put_user_call(fn,x,ptr)                                     \
 ({                                                                     \
        int __ret_pu;                                                   \
-       register __typeof__(*(ptr)) __val_pu asm("%"_ASM_AX);           \
+       __typeof__(ptr) __ptr =3D (ptr);                                  \
+       register __typeof__(*(ptr)) __val_pu asm("%"_ASM_AX) =3D (x);     \
        __chk_user_ptr(ptr);                                            \
-       __val_pu =3D (x);                                                 \
        asm volatile("call __" #fn "_%P[size]"                          \
                     : "=3Dc" (__ret_pu),                                 \
                        ASM_CALL_CONSTRAINT                             \
-                    : "0" (ptr),                                       \
+                    : "0" (__ptr),                                     \
                       "r" (__val_pu),                                  \
                       [size] "i" (sizeof(*(ptr)))                      \
                     :"ebx");                                           \


at least gets us

0000000000004d60 <pu_test>:
    4d60:       53                      push   %rbx
    4d61:       be 05 00 00 00          mov    $0x5,%esi
    4d66:       bf 04 00 00 00          mov    $0x4,%edi
    4d6b:       e8 00 00 00 00          callq  4d70 <pu_test+0x10>
                        4d6c: R_X86_64_PC32     get_destination-0x4
    4d70:       48 89 c1                mov    %rax,%rcx
    4d73:       48 b8 78 56 cd ab 34    movabs $0x1234abcd5678,%rax
    4d7a:       12 00 00
    4d7d:       e8 00 00 00 00          callq  4d82 <pu_test+0x22>
                        4d7e: R_X86_64_PC32     __put_user_8-0x4


FWIW, https://gcc.gnu.org/onlinedocs/gcc/Local-Register-Variables.html
does warn about function calls and other things that might clobber the
register variables between the assignment and the use as an input
(though the case of evaluating other input operands is not explicitly
mentioned).

Rasmus

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/356811ab-cb08-7685-ca01-fe58b5654953%40rasmusvillemoes.dk.
